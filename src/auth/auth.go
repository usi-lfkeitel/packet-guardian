// This source file is part of the Packet Guardian project.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package auth

import (
	"net/http"
	"strings"

	"github.com/lfkeitel/verbose/v4"
	"github.com/packet-guardian/packet-guardian/src/common"
	"github.com/packet-guardian/packet-guardian/src/models/stores"
)

type authenticator interface {
	checkLogin(username, password string, r *http.Request, users stores.UserStore) bool
}

var authFunctions = make(map[string]authenticator)

// LoginUser will verify the username and password against several login methods
// If one method succeeds, true will be returned. False otherwise.
func LoginUser(w http.ResponseWriter, r *http.Request, users stores.UserStore) bool {
	if r.FormValue("password") == "" || r.FormValue("username") == "" {
		return false
	}

	e := common.GetEnvironmentFromContext(r)
	username := strings.ToLower(r.FormValue("username"))
	for _, method := range e.Config.Auth.AuthMethod {
		if authMethod, ok := authFunctions[method]; ok {
			if authMethod.checkLogin(username, r.FormValue("password"), r, users) {
				return SetLoginUser(w, r, username, method)
			}
		}
	}
	e.Log.WithFields(verbose.Fields{
		"username": username,
		"package":  "auth",
	}).Info("Failed login")
	return false
}

// SetLoginUser sets up the session to be loggedin with a specific username.
// Method is the authentication mechanism used.
func SetLoginUser(w http.ResponseWriter, r *http.Request, username, method string) bool {
	e := common.GetEnvironmentFromContext(r)
	sess := common.GetSessionFromContext(r)
	sess.Set("loggedin", true)
	sess.Set("username", username)
	sess.Set("_authMethod", method)

	if err := sess.Save(r, w); err != nil {
		e.Log.WithField("error", err).Error("Failed to save login session")
		return false
	}

	e.Log.WithFields(verbose.Fields{
		"username": username,
		"method":   method,
		"action":   "login",
		"package":  "auth",
	}).Info("Logged in user")
	return true
}

// CheckLogin returns if a username and password combo are valid. LoginUser
// and CheckLogin perform the same check. The only difference is LoginUser
// will setup a server-side session for the request. CheckLogin doesn't
// change anything about the session, it's up to the caller for perform any
// state change.
func CheckLogin(username, password string, r *http.Request, users stores.UserStore) bool {
	if password == "" || username == "" {
		return false
	}

	e := common.GetEnvironmentFromContext(r)
	username = strings.ToLower(username)
	for _, method := range e.Config.Auth.AuthMethod {
		if authMethod, ok := authFunctions[method]; ok {
			if authMethod.checkLogin(username, password, r, users) {
				e.Log.WithFields(verbose.Fields{
					"username": username,
					"method":   method,
					"action":   "login",
					"package":  "auth",
				}).Info("Logged in user")
				return true
			}
		}
	}
	e.Log.WithFields(verbose.Fields{
		"username": username,
		"package":  "auth",
	}).Info("Failed login")
	return false
}

// IsLoggedIn checks the current session and returns if a user is logged in.
func IsLoggedIn(r *http.Request) bool {
	return common.GetSessionFromContext(r).GetBool("loggedin")
}

// LogoutUser modifies the current session to mark the user as logged out.
func LogoutUser(w http.ResponseWriter, r *http.Request) {
	sess := common.GetSessionFromContext(r)
	if !sess.GetBool("loggedin") {
		return
	}

	username := sess.GetString("username", "<unknown>")

	sess.Set("loggedin", false)
	sess.Set("username", "")
	sess.Save(r, w)

	e := common.GetEnvironmentFromContext(r)
	e.Log.WithFields(verbose.Fields{
		"username": username,
		"method":   sess.GetString("_authMethod"),
		"action":   "logout",
		"package":  "auth",
	}).Info("Logged out user")
}
