package server

import (
	"net"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
	"github.com/onesimus-systems/packet-guardian/src/auth"
	"github.com/onesimus-systems/packet-guardian/src/common"
	"github.com/onesimus-systems/packet-guardian/src/controllers"
	"github.com/onesimus-systems/packet-guardian/src/controllers/api"
	"github.com/onesimus-systems/packet-guardian/src/dhcp"
	"github.com/onesimus-systems/packet-guardian/src/models"
	mid "github.com/onesimus-systems/packet-guardian/src/server/middleware"
)

func LoadRoutes(e *common.Environment) http.Handler {
	r := mux.NewRouter().StrictSlash(true)

	// Page routes
	bh := &baseHandlers{e: e}
	r.NotFoundHandler = http.HandlerFunc(bh.notFoundHandler)
	r.HandleFunc("/", bh.rootHandler)
	r.PathPrefix("/public").Handler(http.StripPrefix("/public/", http.FileServer(http.Dir("./public/"))))

	authController := controllers.NewAuthController(e)
	r.HandleFunc("/login", authController.LoginHandler).Methods("GET", "POST")
	r.HandleFunc("/logout", authController.LogoutHandler).Methods("GET")

	manageController := controllers.NewManagerController(e)
	r.HandleFunc("/register", manageController.RegistrationHandler).Methods("GET")
	r.Handle("/manage", mid.CheckAuth(http.HandlerFunc(manageController.ManageHandler))).Methods("GET")

	adminController := controllers.NewAdminController(e)
	r.Handle("/admin", mid.CheckRead(http.HandlerFunc(adminController.DashboardHandler))).Methods("GET")
	s := r.PathPrefix("/admin").Subrouter()
	s.Handle("/manage/{username}", mid.CheckRead(http.HandlerFunc(adminController.ManageHandler))).Methods("GET")
	s.Handle("/search", mid.CheckRead(http.HandlerFunc(adminController.SearchHandler))).Methods("GET")

	// API Routes
	apiRouter := r.PathPrefix("/api").Subrouter()

	deviceApiController := api.NewDeviceController(e)
	s = apiRouter.PathPrefix("/device").Subrouter()
	s.HandleFunc("/register", deviceApiController.RegistrationHandler).Methods("POST")
	s.Handle("/delete", mid.CheckAuthAPI(http.HandlerFunc(deviceApiController.DeleteHandler))).Methods("DELETE")

	// Development Routes
	if e.Dev {
		devController := controllers.NewDevController(e)
		s := r.PathPrefix("/dev").Subrouter()
		s.HandleFunc("/reloadtemp", devController.ReloadTemplates).Methods("GET")
		s.HandleFunc("/reloadconf", devController.ReloadConfiguration).Methods("GET")
	}

	// We're done with Gorilla's special router, convert to an http.Handler
	h := mid.SetSessionInfo(e, r)
	h = mid.Logging(e, h)

	return h
}

type baseHandlers struct {
	e *common.Environment
}

func (b *baseHandlers) rootHandler(w http.ResponseWriter, r *http.Request) {
	ip := strings.Split(r.RemoteAddr, ":")[0]
	reg, err := dhcp.IsRegisteredByIP(b.e, net.ParseIP(ip))
	if err != nil {
		b.e.Log.Errorf("Error checking auto registration IP: %s", err.Error())
	}

	if auth.IsLoggedIn(r) {
		sessionUser := models.GetUserFromContext(r)
		if sessionUser.IsHelpDesk() || sessionUser.IsAdmin() {
			http.Redirect(w, r, "/admin", http.StatusTemporaryRedirect)
		} else {
			http.Redirect(w, r, "/manage", http.StatusTemporaryRedirect)
		}
		return
	}

	if reg {
		http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
	} else {
		http.Redirect(w, r, "/register", http.StatusTemporaryRedirect)
	}
}

func (b *baseHandlers) notFoundHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/favicon.ico" { // Special exception
		http.NotFound(w, r)
		return
	}

	b.e.Log.GetLogger("server").Infof("Path not found %s", r.RequestURI)
	sessionUser := models.GetUserFromContext(r)
	if sessionUser.IsHelpDesk() || sessionUser.IsAdmin() {
		http.Redirect(w, r, "/admin", http.StatusTemporaryRedirect)
	} else {
		http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
	}
}
