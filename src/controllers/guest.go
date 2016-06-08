// This source file is part of the Packet Guardian project.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package controllers

import (
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/usi-lfkeitel/packet-guardian/src/auth"
	"github.com/usi-lfkeitel/packet-guardian/src/common"
	"github.com/usi-lfkeitel/packet-guardian/src/guest"
	"github.com/usi-lfkeitel/packet-guardian/src/models"
)

type Guest struct {
	e *common.Environment
}

func NewGuestController(e *common.Environment) *Guest {
	return &Guest{e: e}
}

func (g *Guest) RegistrationHandler(w http.ResponseWriter, r *http.Request) {
	loggedIn := auth.IsLoggedIn(r) // Only non-guests will be logged in.
	if loggedIn {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	ip := net.ParseIP(strings.Split(r.RemoteAddr, ":")[0])
	reg, _ := models.IsRegisteredByIP(g.e, ip)
	if reg {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	if r.Method == "GET" {
		g.showGuestRegPage(w, r)
		return
	}
	g.checkGuestInfo(w, r)
}

func (g *Guest) showGuestRegPage(w http.ResponseWriter, r *http.Request) {
	label := guest.GetInputLabel(g.e)
	if label == "" {
		g.renderErrorMessage("Guest registrations are currently unavailable. Please notify the IT help desk.", w, r)
		return
	}

	data := map[string]interface{}{
		"policy":         common.LoadPolicyText(g.e.Config.Registration.RegistrationPolicyFile),
		"guestCredLabel": label,
	}

	g.e.Views.NewView("register-guest", r).Render(w, data)
}

func (g *Guest) checkGuestInfo(w http.ResponseWriter, r *http.Request) {
	if !g.e.Config.Guest.Enabled {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	session := common.GetSessionFromContext(r)

	guestCred := r.FormValue("guest-cred")
	guestName := r.FormValue("guest-name")

	if guestCred == "" || guestName == "" {
		session.AddFlash("Please fill in all required fields")
		g.showGuestRegPage(w, r)
		return
	}

	// TODO: Check ban filter for email or phone number
	verifyCode := guest.GenerateGuestCode()
	session.Set("_verify-code", verifyCode)
	session.Set("_expires", time.Now().Add(time.Duration(g.e.Config.Guest.VerifyCodeExpiration)*time.Minute).Unix())
	session.Set("_guest-credential", guestCred)
	session.Set("_guest-name", guestName)
	session.Save(r, w)
	if err := guest.SendGuestCode(g.e, guestCred, verifyCode); err != nil {
		session.AddFlash(err.Error())
		g.showGuestRegPage(w, r)
		return
	}
	g.e.Log.Debugf("Verification Code: %s", verifyCode)
	http.Redirect(w, r, "/register/guest/verify", http.StatusSeeOther)
}

func (g *Guest) VerificationHandler(w http.ResponseWriter, r *http.Request) {
	if !g.e.Config.Guest.Enabled {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	loggedIn := auth.IsLoggedIn(r)
	if loggedIn {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	ip := net.ParseIP(strings.Split(r.RemoteAddr, ":")[0])
	reg, _ := models.IsRegisteredByIP(g.e, ip)
	if reg {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	session := common.GetSessionFromContext(r)
	if session.GetString("_verify-code") == "" {
		http.Redirect(w, r, "/register/guest", http.StatusSeeOther)
		return
	}

	if r.Method == "GET" {
		g.showGuestVerifyPage(w, r)
		return
	}
	g.verifyGuestRegistration(w, r)
}

func (g *Guest) showGuestVerifyPage(w http.ResponseWriter, r *http.Request) {
	g.e.Views.NewView("register-guest-verify", r).Render(w, nil)
}

func (g *Guest) verifyGuestRegistration(w http.ResponseWriter, r *http.Request) {
	session := common.GetSessionFromContext(r)
	if session.GetInt64("_expires") < time.Now().Unix() {
		session.AddFlash("Verification code has expired")
		session.Save(r, w)
		http.Redirect(w, r, "/register/guest", http.StatusSeeOther)
		return
	}

	if session.GetString("_verify-code") != strings.ToUpper(r.FormValue("verify-code")) {
		session.AddFlash("Incorrect verification code")
		g.showGuestVerifyPage(w, r)
		return
	}

	session.Delete(r, w)
	if err := guest.RegisterDevice(
		g.e,
		session.GetString("_guest-name"),
		session.GetString("_guest-credential"),
		r,
	); err != nil {
		g.renderErrorMessage(err.Error(), w, r)
		return
	}
	g.renderMessage("Please disconnect your computer and reconnect to the network", w, r)
}

func (g *Guest) renderErrorMessage(message string, w http.ResponseWriter, r *http.Request) {
	data := map[string]interface{}{
		"msg":   message,
		"error": true,
	}
	g.e.Views.NewView("register-guest-msg", r).Render(w, data)
}

func (g *Guest) renderMessage(message string, w http.ResponseWriter, r *http.Request) {
	data := map[string]interface{}{
		"msg":   message,
		"error": false,
	}
	g.e.Views.NewView("register-guest-msg", r).Render(w, data)
}