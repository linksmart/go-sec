// Copyright 2014-2016 Fraunhofer Institute for Applied Information Technology FIT

// Package obtainer implements OpenID Connect token obtainment from Keycloak
package obtainer

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/linksmart/go-sec/auth/obtainer"
)

const (
	TokenEndpoint = "/protocol/openid-connect/token"
	DriverName    = "keycloak"
)

type KeycloakObtainer struct{}

func init() {
	// Register the driver as a auth/obtainer
	obtainer.Register(DriverName, &KeycloakObtainer{})
}

type Token struct {
	RefreshToken string `json:"refresh_token"`
	IdToken      string `json:"id_token"`
}

// ObtainToken requests a token in exchange for user credentials.
// This follows the OAuth 2.0 Resource Owner Password Credentials Grant.
// For this flow, the client in Keycloak must have Direct Grant enabled.
func (o *KeycloakObtainer) ObtainToken(serverAddr, username, password, clientID string) (token interface{}, err error) {

	res, err := http.PostForm(serverAddr+TokenEndpoint, url.Values{
		"grant_type": {"password"},
		"client_id":  {clientID},
		"username":   {username},
		"password":   {password},
		"scope":      {"openid"},
	})
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unable to login with username `%s`: %s", username, string(body))
	}

	var keycloakToken Token
	err = json.Unmarshal(body, &keycloakToken)
	if err != nil {
		return nil, fmt.Errorf("error getting the token: %s", err)
	}

	return keycloakToken, nil
}

// TokenString returns the ID Token part of token object
func (o *KeycloakObtainer) TokenString(token interface{}) (tokenString string, err error) {
	if token, ok := token.(Token); ok {
		return token.IdToken, nil
	}
	return "", fmt.Errorf("invalid input token: assertion error")
}

// RenewToken returns the token
//  acquired either from the token object or by requesting a new one using refresh token
func (o *KeycloakObtainer) RenewToken(serverAddr string, oldToken interface{}, clientID string) (newToken interface{}, err error) {
	token, ok := oldToken.(Token)
	if !ok {
		return nil, fmt.Errorf("invalid input token: assertion error")
	}

	parts := strings.Split(token.IdToken, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("malformed jwt id_token")
	}

	// decode the payload of the id_token given in input
	decoded, err := base64.RawStdEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("error decoding the id_token: %s", err)
	}

	var claims struct {
		Expiry int64 `json:"exp"`
	}
	err = json.Unmarshal(decoded, &claims)
	if err != nil {
		return "", fmt.Errorf("error decoding the id_token: %s", err)
	}
	// if id_token is still valid, no need to request a new one
	if claims.Expiry > time.Now().Unix() {
		return token.IdToken, nil
	}

	// get a new token using the refresh_token
	res, err := http.PostForm(serverAddr+TokenEndpoint, url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {clientID},
		"refresh_token": {token.RefreshToken},
	})
	if err != nil {
		return "", err
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return "", err
	}
	if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("error getting a new token: %s", string(body))
	}

	var keycloakToken Token
	err = json.Unmarshal(body, &keycloakToken)
	if err != nil {
		return "", fmt.Errorf("error decoding the new token: %s", err)
	}

	return keycloakToken, nil
}

// Logout expires the ticket (Not applicable in the current flow)
func (o *KeycloakObtainer) RevokeToken(serverAddr string, token interface{}) error {
	// TODO https://www.keycloak.org/docs/latest/securing_apps/#_token_revocation_endpoint
	return nil
}
