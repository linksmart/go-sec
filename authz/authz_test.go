package authz

import (
	"encoding/json"
	"fmt"
	"testing"
)

//type testCases []testCase

type testCase struct {
	path   string
	method string
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
	confJSON := `{
		"enabled": true,
		"rules": [
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
			}
		]
	}`

	allowCases := []testCase{
		{path: "/res", method: "GET", user: "linksmart"},
		{path: "/res/123", method: "GET", user: "linksmart"},
		{path: "/res", method: "GET", groups: []string{"admin"}},
		{path: "/res/123", method: "GET", groups: []string{"admin"}},
		{path: "/res", method: "PUT", groups: []string{"admin"}},
		{path: "/res", method: "DELETE", groups: []string{"admin"}},
	}

	denyCases := []testCase{
		{path: "/res", method: "PUT", user: "linksmart"},
		{path: "/res2", method: "GET", user: "linksmart"},
		{path: "/res", method: "POST", groups: []string{"admin"}},
		{path: "/res2", method: "PUT", groups: []string{"admin"}},
	}

	runAllowDenyTests(confJSON, allowCases, denyCases, t)
}

func TestAuthorized(t *testing.T) {
	confJSON := `{
		"enabled": true,
		"rules": [
			{
				"paths": ["/res"],
				"methods": ["GET"],
				"users": ["john"],
				"groups": [],
				"roles": [],
				"clients": [],
				"denyPathSubstrings": ["secret"]
			},
			{
				"paths": ["/res"],
				"methods": ["GET", "PUT"],
				"users": [],
				"groups": ["editor", "admin"],
				"roles": [],
				"clients": [],
				"denyPathSubstrings": []
			},
			{
				"paths": ["/res"],
				"methods": ["DELETE"],
				"users": [],
				"groups": ["admin"],
				"roles": [],
				"clients": [],
				"denyPathSubstrings": []
			}
		]
	}`

	allowCases := []testCase{
		{path: "/res", method: "GET", user: "john"},
		{path: "/res/123", method: "GET", user: "john"},
		{path: "/res/secret", method: "GET", groups: []string{"editor"}},
		{path: "/res", method: "PUT", groups: []string{"editor"}},
		{path: "/res", method: "PUT", groups: []string{"admin"}},
		{path: "/res", method: "DELETE", groups: []string{"admin"}},
	}

	denyCases := []testCase{
		{path: "/res/secret", method: "GET", user: "john"},
		{path: "/res/secret/2", method: "GET", user: "john"},
		{path: "/res", method: "DELETE", groups: []string{"editor"}},
	}

	runAllowDenyTests(confJSON, allowCases, denyCases, t)
}

func runAllowDenyTests(authzConf string, allowCases, denyCases []testCase, t *testing.T) {
	var conf Conf
	err := json.Unmarshal([]byte(authzConf), &conf)
	if err != nil {
		t.Error(err)
	}

	t.Run("allow", func(t *testing.T) {
		for _, c := range allowCases {
			if !conf.Authorized(c.path, c.method, c.Claims()) {
				t.Logf("Did not allow %+v", c)
				t.Fail()
			}
		}
	})

	t.Run("deny", func(t *testing.T) {
		for _, c := range denyCases {
			if conf.Authorized(c.path, c.method, c.Claims()) {
				t.Logf("Did not deny %+v", c)
				t.Fail()
			}
		}
	})

	if t.Failed() {
		b, _ := json.MarshalIndent(conf.Rules, "", "\t")
		t.Logf("Given rules: %s", b)
	}
}
