// Copyright 2014-2016 Fraunhofer Institute for Applied Information Technology FIT

package validator

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	_ "github.com/linksmart/go-sec/auth/keycloak/obtainer"
	"github.com/linksmart/go-sec/auth/obtainer"
)

// Handler is a http.Handler that validates tickets and performs optional authorization
func (v *Validator) Handler(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {

		// Authorization header
		Authorization := r.Header.Get("Authorization")
		if Authorization == "" {
			if v.authz != nil {
				if ok := v.authz.Authorized(r.URL.Path, r.Method, "", []string{"anonymous"}); ok {
					// Anonymous access, proceed to the next handler
					next.ServeHTTP(w, r)
					return
				}
			}
			errorResponse(w, http.StatusUnauthorized, "unauthorized request.")
			return
		}

		parts := strings.SplitN(Authorization, " ", 2)
		if len(parts) != 2 {
			errorResponse(w, http.StatusBadRequest, "invalid format for Authorization header value")
			return
		}
		method, value := parts[0], parts[1]

		switch {
		case method == "Bearer": // i.e. Authorization: Bearer token
			statuscode, err := v.validationChain(value, r.URL.Path, r.Method)
			if err != nil {
				errorResponse(w, statuscode, err.Error())
				return
			}

		case method == "Basic" && v.basicEnabled: // i.e. Authorization: Basic base64_encoded_credentials
			token, statuscode, err := v.basicAuth(value)
			if err != nil {
				errorResponse(w, statuscode, err.Error())
				return
			}
			statuscode, err = v.validationChain(token, r.URL.Path, r.Method)
			if err != nil {
				errorResponse(w, statuscode, err.Error())
				return
			}

		default:
			errorResponse(w, http.StatusUnauthorized, "unsupported Authorization method:", method)
			return
		}

		// Successful validation, proceed to the next handler
		next.ServeHTTP(w, r)
		return
	}
	return http.HandlerFunc(fn)
}

// validationChain validates a token and performs authorization
func (v *Validator) validationChain(tokenString string, path, method string) (int, error) {
	// Validate Token
	valid, profile, err := v.driver.Validate(v.serverAddr, v.clientID, tokenString)
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("validation error: %s", err)
	}
	if !valid {
		if profile != nil && profile.Status != "" {
			return http.StatusUnauthorized, fmt.Errorf("unauthorized request: %s", profile.Status)
		}
		return http.StatusUnauthorized, fmt.Errorf("unauthorized request")
	}
	// Check for optional authorization
	if v.authz.Enabled {
		if ok := v.authz.Authorized(path, method, profile.Username, profile.Groups); !ok {
			return http.StatusForbidden, fmt.Errorf("access denied for user: %s, group membership: %v", profile.Username, profile.Groups)
		}
	}
	return http.StatusOK, nil
}

// Cached clients for Basic auth
var clients = make(map[string]*obtainer.Client)

// basicAuth generates a token for the given credentials
//	Tokens are cached and are only regenerated if no longer valid
func (v *Validator) basicAuth(credentials string) (string, int, error) {

	b, err := base64.StdEncoding.DecodeString(credentials)
	if err != nil {
		return "", http.StatusBadRequest, fmt.Errorf("basic auth: invalid encoding: %s", err)
	}

	client, found := clients[credentials]
	if !found {
		pair := strings.SplitN(string(b), ":", 2)
		if len(pair) != 2 {
			return "", http.StatusBadRequest, fmt.Errorf("basic auth: invalid format for credentials")
		}

		// Setup ticket client
		client, err = obtainer.NewClient(v.driverName, v.serverAddr, pair[0], pair[1], v.clientID)
		if err != nil {
			return "", http.StatusInternalServerError, fmt.Errorf("basic auth: unable to create a client to obtain tokens: %s", err)
		}

		clients[credentials] = client
	}

	tokenString, err := client.Obtain()
	if err != nil {
		return "", http.StatusUnauthorized, fmt.Errorf("basic auth: unable to obtain ticket: %s", err)
	}

	valid, _, err := v.driver.Validate(v.serverAddr, v.clientID, tokenString)
	if err != nil {
		return "", http.StatusInternalServerError, fmt.Errorf("basic auth: validation error: %s", err)
	}
	if !valid {
		tokenString, err = client.Renew()
		if err != nil {
			return "", http.StatusUnauthorized, fmt.Errorf("basic auth: unable to renew token: %s", err)
		}
	}
	return tokenString, http.StatusOK, nil
}

// errorResponse writes error to HTTP ResponseWriter
func errorResponse(w http.ResponseWriter, code int, msgs ...interface{}) {
	b, _ := json.Marshal(map[string]interface{}{
		"code":    code,
		"message": fmt.Sprint(msgs...),
	})
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(b)
}
