// This source file is part of the Packet Guardian project.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package common

import (
	"errors"
	"net/http"
	"os"

	"github.com/gorilla/sessions"
)

// Key is for contexts
type Key int

// Session values keys
const (
	SessionKey     Key = 0
	SessionUserKey Key = 1
	SessionEnvKey  Key = 2
	SessionIPKey   Key = 3
)

// SessionStore wraps a Gorilla session and adds extra functionality.
type SessionStore struct {
	sessions.Store
	sessionName string
}

// NewSessionStore creates a new store based the application configuration.
func NewSessionStore(e *Environment) (*SessionStore, error) {
	switch e.Config.Webserver.SessionStore {
	case "filesystem":
		return newFilesystemStore(e)
	case "database":
		return newDatabaseStore(e)
	}
	return nil, errors.New("Invalid setting for SessionStore")
}

func newFilesystemStore(e *Environment) (*SessionStore, error) {
	if e.Config.Webserver.SessionsDir == "" {
		e.Config.Webserver.SessionsDir = "sessions"
	}
	if e.Config.Webserver.SessionsAuthKey == "" {
		return nil, errors.New("No session authentication key given in configuration")
	}

	err := os.MkdirAll(e.Config.Webserver.SessionsDir, 0700)
	if err != nil {
		return nil, err
	}

	fs := sessions.NewFilesystemStore(e.Config.Webserver.SessionsDir, getKeyPairs(e.Config)...)
	fs.Options = &sessions.Options{
		Path:   "/",
		MaxAge: 0, // Expire on browser close
	}
	store := &SessionStore{
		Store:       fs,
		sessionName: e.Config.Webserver.SessionName,
	}

	return store, nil
}

func newDatabaseStore(e *Environment) (*SessionStore, error) {
	var store sessions.Store
	var err error
	options := &Options{
		Path:      "/",
		MaxAge:    0,
		HTTPOnly:  true,
		TableName: "sessions",
	}
	switch e.DB.Driver {
	case "mysql":
		store, err = newDBStore(
			e.DB,
			options,
			getKeyPairs(e.Config)...,
		)
	}
	if store == nil {
		return nil, errors.New("Non-supported database driver")
	}
	return &SessionStore{
		Store:       store,
		sessionName: e.Config.Webserver.SessionName,
	}, err
}

func getKeyPairs(config *Config) [][]byte {
	sessKeyPair := make([][]byte, 1)
	sessKeyPair[0] = []byte(config.Webserver.SessionsAuthKey)
	if config.Webserver.SessionsEncryptKey != "" {
		sessKeyPair = append(sessKeyPair, []byte(config.Webserver.SessionsEncryptKey))
	}
	return sessKeyPair
}

// GetSession returns a session based on the http request.
func (s *SessionStore) GetSession(r *http.Request) *Session {
	sess, _ := s.Get(r, s.sessionName)
	return &Session{sess}
}

// Session is a wrapper around Gorilla sessions to provide access methods
type Session struct {
	*sessions.Session
}

// Delete a session.
func (s *Session) Delete(r *http.Request, w http.ResponseWriter) error {
	// This relies on a patched version of gorilla sessions. The upstream version
	// has a bug where MaxAge < 0 is considered "end of browser session" instead
	// of "delete right now".
	s.Options.MaxAge = -1
	return s.Save(r, w)
}

// Get a value from the session object
func (s *Session) Get(key interface{}, def ...interface{}) interface{} {
	if val, ok := s.Values[key]; ok {
		return val
	}
	if len(def) > 0 {
		return def[0]
	}
	return nil
}

// Set a value to the session object
func (s *Session) Set(key, val interface{}) {
	s.Values[key] = val
}

// GetBool takes the same arguments as Get but def must be a bool type.
func (s *Session) GetBool(key interface{}, def ...bool) bool {
	if v := s.Get(key); v != nil {
		return v.(bool)
	}
	if len(def) > 0 {
		return def[0]
	}
	return false
}

// GetString takes the same arguments as Get but def must be a string type.
func (s *Session) GetString(key interface{}, def ...string) string {
	if v := s.Get(key); v != nil {
		return v.(string)
	}
	if len(def) > 0 {
		return def[0]
	}
	return ""
}

// GetInt takes the same arguments as Get but def must be an int type.
func (s *Session) GetInt(key interface{}, def ...int) int {
	if v := s.Get(key); v != nil {
		return v.(int)
	}
	if len(def) > 0 {
		return def[0]
	}
	return 0
}

// GetInt64 takes the same arguments as Get but def must be an int type.
func (s *Session) GetInt64(key interface{}, def ...int64) int64 {
	if v := s.Get(key); v != nil {
		return v.(int64)
	}
	if len(def) > 0 {
		return def[0]
	}
	return 0
}

// NewTestSession creates a session for testing.
func NewTestSession() *Session {
	return &Session{
		sessions.NewSession(&TestStore{}, "something"),
	}
}

// TestStore is a mock session store for testing.
type TestStore struct{}

// Get session
func (t *TestStore) Get(r *http.Request, name string) (*sessions.Session, error) { return nil, nil }

// New session
func (t *TestStore) New(r *http.Request, name string) (*sessions.Session, error) { return nil, nil }

// Save session
func (t *TestStore) Save(r *http.Request, w http.ResponseWriter, s *sessions.Session) error {
	return nil
}
