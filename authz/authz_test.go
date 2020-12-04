package authz

import (
	"encoding/json"
	"fmt"
	"testing"
)

type testCase struct {
	path      string
	method    string
	anonymous bool
	// claims
	user     string
	groups   []string
	roles    []string
	clientID string
}

func (t testCase) Stringify() string {
	return fmt.Sprintf("%v", t)
}

func (t testCase) Claims() *Claims {
	if t.anonymous {
		return nil
	}
	return &Claims{
		Username: t.user,
		Groups:   t.groups,
		Roles:    t.roles,
		ClientID: t.clientID,
		Status:   "n/a",
	}
}

// Test examples on the wiki
func TestAuthorizedExample(t *testing.T) {
	confRules := `[
		{
			"paths": ["/res"],
			"methods": ["GET"],
			"users": ["linksmart"],
			"groups": ["admin"]
		},
		{
			"paths": ["/res"],
			"methods": ["PUT", "DELETE"],
			"users": [],
			"groups": ["admin"]
		},
		{
			"paths": ["/public"],
			"methods": ["GET"],
			"groups": ["anonymous"]
		}
	]`

	allowCases := []testCase{
		{path: "/res", method: "GET", user: "linksmart"},
		{path: "/res/123", method: "GET", user: "linksmart"},
		{path: "/res", method: "GET", groups: []string{"admin"}},
		{path: "/res/123", method: "GET", groups: []string{"admin"}},
		{path: "/res", method: "PUT", groups: []string{"admin"}},
		{path: "/res", method: "DELETE", groups: []string{"admin"}},
		{path: "/public", method: "GET", anonymous: true},
	}

	denyCases := []testCase{
		{path: "/res", method: "PUT", user: "linksmart"},
		{path: "/res2", method: "GET", user: "linksmart"},
		{path: "/res", method: "POST", groups: []string{"admin"}},
		{path: "/res2", method: "PUT", groups: []string{"admin"}},
		{path: "/res", method: "GET", anonymous: true},
	}

	runAllowDenyTests(confRules, allowCases, denyCases, t)
}

func TestAuthorized(t *testing.T) {
	confRules := `[
		{
			"paths": ["/res"],
			"methods": ["GET"],
			"users": ["john"],
			"groups": [],
			"roles": ["customer"],
			"clients": [],
			"denyPathSubstrings": ["secret"]
		},
		{
			"paths": ["/res"],
			"methods": ["GET", "PUT"],
			"users": [],
			"groups": ["editor"],
			"roles": ["editor"],
			"clients": ["editor-tool"],
			"denyPathSubstrings": []
		},
		{
			"paths": ["/res"],
			"methods": ["DELETE","GET", "PUT"],
			"users": [],
			"groups": ["admin"],
			"roles": ["admin"],
			"clients": ["admin-tool"],
			"denyPathSubstrings": []
		}
	]`

	allowCases := []testCase{
		{path: "/res", method: "GET", user: "john"},
		{path: "/res/123", method: "GET", user: "john"},
		{path: "/res/secret", method: "GET", groups: []string{"editor"}},
		{path: "/res", method: "PUT", groups: []string{"editor"}},
		{path: "/res", method: "PUT", groups: []string{"admin"}},
		{path: "/res", method: "DELETE", groups: []string{"admin"}},
		{path: "/res/secret", method: "GET", clientID: "editor-tool"},
		{path: "/res", method: "PUT", clientID: "editor-tool"},
		{path: "/res", method: "PUT", clientID: "admin-tool"},
		{path: "/res", method: "DELETE", groups: []string{"admin"}, user: "john"},
		{path: "/res", method: "GET", groups: []string{"admin"}, user: "john"},
		{path: "/res", method: "DELETE", groups: []string{"editor"},roles: []string{"admin"}},
		{path: "/res/CaseSensitiveSecret", method: "GET", user: "john"},
	}

	denyCases := []testCase{
		{path: "/res/secret", method: "GET", user: "john"},
		{path: "/res/secret/2", method: "GET", user: "john"},
		{path: "/res/substringsecret", method: "GET", user: "john"},
		{path: "/res", method: "DELETE", groups: []string{"developer"}},
	}

	runAllowDenyTests(confRules, allowCases, denyCases, t)
}

func runAllowDenyTests(authzRules string, allowCases, denyCases []testCase, t *testing.T) {
	var rules Rules
	err := json.Unmarshal([]byte(authzRules), &rules)
	if err != nil {
		t.Fatalf("Error loading authz config json: %s", err)
	}

	t.Run("allow", func(t *testing.T) {
		for _, c := range allowCases {
			if !rules.Authorized(c.path, c.method, c.Claims()) {
				t.Logf("Did not allow %+v", c)
				t.Fail()
			}
		}
	})

	t.Run("deny", func(t *testing.T) {
		for _, c := range denyCases {
			if rules.Authorized(c.path, c.method, c.Claims()) {
				t.Logf("Did not deny %+v", c)
				t.Fail()
			}
		}
	})

	if t.Failed() {
		b, _ := json.MarshalIndent(rules, "", "\t")
		t.Logf("Given rules: %s", b)
	}
}
