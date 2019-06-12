// This source file is part of the Packet Guardian project.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package auth

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/packet-guardian/packet-guardian/src/common"
	"github.com/packet-guardian/packet-guardian/src/models"
	"github.com/packet-guardian/packet-guardian/src/models/stores"
)

func init() {
	authFunctions["a1"] = &testAuthOne{}
	authFunctions["a2"] = &testAuthTwo{}
}

type testAuthOne struct{}

func (t *testAuthOne) checkLogin(username, password string, r *http.Request, users stores.UserStore) bool {
	return (username == "tester1")
}

type testAuthTwo struct{}

func (t *testAuthTwo) checkLogin(username, password string, r *http.Request, users stores.UserStore) bool {
	return (username == "tester2")
}

func TestLoginUser(t *testing.T) {
	e := common.NewTestEnvironment()
	e.Config.Auth.AuthMethod = []string{"a1", "a2"}

	session := common.NewTestSession()

	testUserStore := &stores.TestUserStore{}

	req, _ := http.NewRequest("", "", nil)
	req = common.SetEnvironmentToContext(req, e)
	req = common.SetSessionToContext(req, session)

	req.Form = make(url.Values)

	// Test first auth method
	req.Form.Add("username", "tester1")
	req.Form.Add("password", "somePassword")
	if !LoginUser(httptest.NewRecorder(), req, testUserStore) {
		t.Error("Login failed for tester1. Expected true, got false")
	}
	if session.GetString("_authMethod") != "a1" {
		t.Errorf("Incorrect auth method. Expected a1, got %s", session.GetString("_authMethod"))
	}
	if !session.GetBool("loggedin") {
		t.Error("Incorrect session value \"loggedin\". Expected true, got false")
	}
	if session.GetString("username") != "tester1" {
		t.Errorf("Incorrect session username. Expected \"tester1\", got %s", session.GetString("username"))
	}

	// Test second auth method
	req.Form.Set("username", "tester2")
	req.Form.Set("password", "somePassword")
	if !LoginUser(httptest.NewRecorder(), req, testUserStore) {
		t.Error("Login failed for tester2. Expected true, got false")
	}
	if session.GetString("_authMethod") != "a2" {
		t.Errorf("Incorrect auth method. Expected a1, got %s", session.GetString("_authMethod"))
	}
	if !session.GetBool("loggedin") {
		t.Error("Incorrect session value \"loggedin\". Expected true, got false")
	}
	if session.GetString("username") != "tester2" {
		t.Errorf("Incorrect session username. Expected \"tester2\", got %s", session.GetString("username"))
	}
}

func TestIsLoggedIn(t *testing.T) {
	session := common.NewTestSession()
	req, _ := http.NewRequest("", "", nil)
	req = common.SetSessionToContext(req, session)

	session.Set("loggedin", true)
	if !IsLoggedIn(req) {
		t.Error("IsLoggedIn failed. Expected true, got false")
	}

	session.Set("loggedin", false)
	if IsLoggedIn(req) {
		t.Error("IsLoggedIn failed. Expected false, got true")
	}
}

func TestLogoutUser(t *testing.T) {
	e := common.NewTestEnvironment()

	session := common.NewTestSession()
	session.Set("loggedin", true)
	session.Set("username", "Tester")

	user := &models.User{
		Username: "Tester",
	}

	req, _ := http.NewRequest("", "", nil)
	req = common.SetEnvironmentToContext(req, e)
	req = common.SetSessionToContext(req, session)
	req = models.SetUserToContext(req, user)

	LogoutUser(httptest.NewRecorder(), req)
	if session.GetBool("loggedin", true) {
		t.Error("Failed to logout user. Expected false, got true")
	}
	username := session.GetString("username", "Tester")
	if username != "" {
		t.Errorf("Failed to logout user. Expected \"\", got %s", username)
	}
}
