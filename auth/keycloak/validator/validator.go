// Copyright 2014-2016 Fraunhofer Institute for Applied Information Technology FIT

// Package validator implements OpenID Connect token validation obtained from Keycloak
package validator

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/linksmart/go-sec/auth/validator"
)

const DriverName = "keycloak"

type KeycloakValidator struct {
	publicKey *rsa.PublicKey
}

func init() {
	// Register the driver as a auth/validator
	validator.Register(DriverName, &KeycloakValidator{})
}

// Validate validates the token
func (v *KeycloakValidator) Validate(serverAddr, clientID, tokenString string) (bool, *validator.UserProfile, error) {

	if v.publicKey == nil {
		// Get the public key
		res, err := http.Get(serverAddr)
		if err != nil {
			return false, nil, fmt.Errorf("error getting the public key from the authentication server: %s", err)
		}
		defer res.Body.Close()

		var body struct {
			PublicKey string `json:"public_key"`
		}
		err = json.NewDecoder(res.Body).Decode(&body)
		if err != nil {
			return false, nil, fmt.Errorf("error getting the public key from the authentication server response: %s", err)
		}

		// Decode the public key
		decoded, err := base64.StdEncoding.DecodeString(body.PublicKey)
		if err != nil {
			return false, nil, fmt.Errorf("error decoding the authentication server public key: %s", err)
		}

		// Parse the public key
		parsed, err := x509.ParsePKIXPublicKey(decoded)
		if err != nil {
			return false, nil, fmt.Errorf("error pasring the authentication server public key: %s", err)
		}

		var ok bool
		if v.publicKey, ok = parsed.(*rsa.PublicKey); !ok {
			return false, nil, fmt.Errorf("the authentication server's public key type is not RSA")
		}
	}

	type expectedClaims struct {
		jwt.StandardClaims
		Type              string   `json:"typ"`
		PreferredUsername string   `json:"preferred_username"`
		Groups            []string `json:"groups"`
	}
	// Parse the jwt id_token
	token, err := jwt.ParseWithClaims(tokenString, &expectedClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Make sure that the algorithm is RS256
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unable to validate authentication token. Unexpected signing method: %v", token.Header["alg"])
		}
		return v.publicKey, nil
	})
	if err != nil {
		return false, &validator.UserProfile{Status: fmt.Sprintf("error parsing jwt token: %s", err)}, nil
	}

	// Check the validation errors
	if !token.Valid {
		if ve, ok := err.(*jwt.ValidationError); ok {
			if ve.Errors&jwt.ValidationErrorMalformed != 0 {
				return false, &validator.UserProfile{Status: fmt.Sprintf("Invalid token.")}, nil
			} else if ve.Errors&(jwt.ValidationErrorExpired|jwt.ValidationErrorNotValidYet) != 0 {
				return false, &validator.UserProfile{Status: fmt.Sprintf("Token is either expired or not active yet")}, nil
			} else {
				return false, &validator.UserProfile{Status: fmt.Sprintf("Error validating the token: %s", err)}, nil
			}
		} else {
			return false, &validator.UserProfile{Status: fmt.Sprintf("Invalid token: %s", err)}, nil
		}
	}

	// Validate the claims and get user data
	if claims, ok := token.Claims.(*expectedClaims); ok {
		if claims.Type != "ID" {
			return false, &validator.UserProfile{Status: fmt.Sprintf("Wrong token type `%s` for accessing resource. Expecting type `ID`.", claims.Type)}, nil
		}
		if claims.Audience != clientID {
			return false, &validator.UserProfile{Status: fmt.Sprintf("The token is issued for another client: %s", claims.Audience)}, nil
		}
		if claims.Issuer != serverAddr {
			return false, &validator.UserProfile{Status: fmt.Sprintf("The token is issued by another provider: %s", claims.Issuer)}, nil
		}

		var profile validator.UserProfile
		profile.Username = claims.PreferredUsername
		profile.Groups = claims.Groups
		return true, &profile, nil
	}
	return false, nil, fmt.Errorf("unable to extract claims from the jwt id_token")
}
