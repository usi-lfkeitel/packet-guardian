// This source file is part of the Packet Guardian project.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package server

import (
	"fmt"
	"net/http"
	"net/http/pprof"
	"runtime"
	"strings"

	"github.com/dchest/captcha"
	assetfs "github.com/elazarl/go-bindata-assetfs"
	"github.com/gorilla/context"
	"github.com/julienschmidt/httprouter"
	"github.com/lfkeitel/verbose/v4"

	"github.com/packet-guardian/dhcp-lib"
	"github.com/packet-guardian/packet-guardian/src/auth"
	"github.com/packet-guardian/packet-guardian/src/bindata"
	"github.com/packet-guardian/packet-guardian/src/common"
	"github.com/packet-guardian/packet-guardian/src/controllers"
	"github.com/packet-guardian/packet-guardian/src/controllers/api"
	"github.com/packet-guardian/packet-guardian/src/models"
	"github.com/packet-guardian/packet-guardian/src/models/stores"
	mid "github.com/packet-guardian/packet-guardian/src/server/middleware"
)

func LoadRoutes(e *common.Environment, stores stores.StoreCollection) http.Handler {
	r := httprouter.New()
	r.NotFound = http.HandlerFunc(notFoundHandler)

	r.Handler("GET", "/", midStack(e, stores, &rootHandler{leases: stores.Leases}))
	r.ServeFiles(
		"/public/*filepath",
		&assetfs.AssetFS{
			Asset:     bindata.GetAsset,
			AssetDir:  bindata.GetAssetDir,
			AssetInfo: bindata.GetAssetInfo,
			Prefix:    "public"})

	authController := controllers.NewAuthController(e, stores.Users)
	r.Handler("GET", "/login", midStack(e, stores, http.HandlerFunc(authController.LoginHandler)))
	r.Handler("POST", "/login", midStack(e, stores, http.HandlerFunc(authController.LoginHandler)))
	r.Handler("GET", "/logout", midStack(e, stores, http.HandlerFunc(authController.LogoutHandler)))
	r.Handler("GET", "/openid", midStack(e, stores, http.HandlerFunc(authController.OpenIDHandler)))

	manageController := controllers.NewManagerController(e, stores.Devices, stores.Leases)
	r.Handler("GET", "/register", midStack(e, stores, http.HandlerFunc(manageController.RegistrationHandler)))
	r.Handler("GET", "/manage", midStack(e, stores, mid.CheckAuth(http.HandlerFunc(manageController.ManageHandler))))

	guestController := controllers.NewGuestController(e, stores.Users, stores.Devices, stores.Leases)
	r.Handler("GET", "/register/guest", midStack(e, stores, mid.CheckGuestReg(
		http.HandlerFunc(guestController.RegistrationHandler), e, stores.Leases)))
	r.Handler("POST", "/register/guest", midStack(e, stores, mid.CheckGuestReg(
		http.HandlerFunc(guestController.RegistrationHandler), e, stores.Leases)))
	r.Handler("GET", "/register/guest/verify", midStack(e, stores, mid.CheckGuestReg(
		http.HandlerFunc(guestController.VerificationHandler), e, stores.Leases)))
	r.Handler("POST", "/register/guest/verify", midStack(e, stores, mid.CheckGuestReg(
		http.HandlerFunc(guestController.VerificationHandler), e, stores.Leases)))

	r.Handler("GET", "/admin/*a", midStack(e, stores, adminRouter(e, stores)))
	r.Handler("GET", "/api/*a", midStack(e, stores, apiRouter(e, stores)))
	r.Handler("POST", "/api/*a", midStack(e, stores, apiRouter(e, stores)))
	r.Handler("DELETE", "/api/*a", midStack(e, stores, apiRouter(e, stores)))

	r.Handler("GET", "/captcha/*a", captcha.Server(captcha.StdWidth, captcha.StdHeight))

	if e.IsDev() {
		r.Handler("GET", "/debug/*a", midStack(e, stores, debugRouter(e)))
		e.Log.Debug("Profiling enabled")
	}

	h := mid.Logging(r, e) // Logging
	h = mid.Panic(h, e)    // Panic catcher
	return h
}

func midStack(e *common.Environment, stores stores.StoreCollection, h http.Handler) http.Handler {
	h = mid.BlacklistCheck(h, e, stores.Devices, stores.Leases) // Enforce a blacklist check
	h = mid.Cache(h, e)                                         // Set cache headers if needed
	h = mid.SetSessionInfo(h, e, stores.Users)                  // Adds Environment and user information to requet context
	h = context.ClearHandler(h)                                 // Clear Gorilla sessions
	return h
}

func debugRouter(e *common.Environment) http.Handler {
	r := httprouter.New()
	r.NotFound = http.HandlerFunc(notFoundHandler)

	r.HandlerFunc("GET", "/debug/pprof", pprof.Index)
	r.HandlerFunc("GET", "/debug/pprof/cmdline", pprof.Cmdline)
	r.HandlerFunc("GET", "/debug/pprof/profile", pprof.Profile)
	r.HandlerFunc("GET", "/debug/pprof/symbol", pprof.Symbol)
	r.HandlerFunc("GET", "/debug/pprof/trace", pprof.Trace)
	// Manually add support for paths linked to by index page at /debug/pprof/
	r.Handler("GET", "/debug/pprof/goroutine", pprof.Handler("goroutine"))
	r.Handler("GET", "/debug/pprof/heap", pprof.Handler("heap"))
	r.Handler("GET", "/debug/pprof/threadcreate", pprof.Handler("threadcreate"))
	r.Handler("GET", "/debug/pprof/block", pprof.Handler("block"))

	r.HandlerFunc("GET", "/debug/heap-stats", heapStats)

	h := mid.CheckAdmin(r)
	h = mid.CheckAuth(h)
	return h
}

func heapStats(w http.ResponseWriter, r *http.Request) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	fmt.Fprintf(w,
		"HeapSys: %d, HeapAlloc: %d, HeapIdle: %d, HeapReleased: %d\n",
		m.HeapSys,
		m.HeapAlloc,
		m.HeapIdle,
		m.HeapReleased,
	)
}

func adminRouter(e *common.Environment, stores stores.StoreCollection) http.Handler {
	r := httprouter.New()
	r.NotFound = http.HandlerFunc(notFoundHandler)

	adminController := controllers.NewAdminController(e, stores)
	r.GET("/admin/", adminController.DashboardHandler)
	r.GET("/admin/search", adminController.SearchHandler)
	r.GET("/admin/manage/user/:username", adminController.ManageHandler)
	r.GET("/admin/manage/device/:mac", adminController.ShowDeviceHandler)
	r.GET("/admin/users", adminController.AdminUserListHandler)
	r.GET("/admin/users/:username", adminController.AdminUserHandler)
	r.GET("/admin/reports", adminController.ReportHandler)
	r.GET("/admin/reports/:report", adminController.ReportHandler)

	h := mid.CheckAdmin(r)
	h = mid.CheckAuth(h)
	return h
}

func apiRouter(e *common.Environment, stores stores.StoreCollection) http.Handler {
	r := httprouter.New()

	deviceAPIController := api.NewDeviceController(e, stores.Users, stores.Devices, stores.Leases)
	r.POST("/api/device", deviceAPIController.RegistrationHandler)            // handles permission checks
	r.DELETE("/api/device/user/:username", deviceAPIController.DeleteHandler) // handles permission checks
	r.POST("/api/device/reassign",
		mid.CheckPermissions(deviceAPIController.ReassignHandler,
			mid.PermsCanAny(models.ReassignDevice)))
	// handles permission checks
	r.POST("/api/device/mac/:mac/description", deviceAPIController.EditDescriptionHandler)
	r.POST("/api/device/mac/:mac/expiration",
		mid.CheckPermissions(deviceAPIController.EditExpirationHandler,
			mid.PermsCanAny(models.EditDevice)))
	r.POST("/api/device/mac/:mac/flag",
		mid.CheckPermissions(deviceAPIController.EditFlaggedHandler,
			mid.PermsCanAny(models.EditDevice)))
	r.GET("/api/device/:mac", deviceAPIController.GetDeviceHandler)

	blacklistController := api.NewBlacklistController(e, stores.Users, stores.Devices)
	r.POST("/api/blacklist/user/:username",
		mid.CheckPermissions(blacklistController.BlacklistUserHandler,
			mid.PermsCanAny(models.ManageBlacklist)))
	r.DELETE("/api/blacklist/user/:username",
		mid.CheckPermissions(blacklistController.BlacklistUserHandler,
			mid.PermsCanAny(models.ManageBlacklist)))

	r.POST("/api/blacklist/device",
		mid.CheckPermissions(blacklistController.BlacklistDeviceHandler,
			mid.PermsCanAny(models.ManageBlacklist)))
	r.DELETE("/api/blacklist/device",
		mid.CheckPermissions(blacklistController.BlacklistDeviceHandler,
			mid.PermsCanAny(models.ManageBlacklist)))

	userAPIController := api.NewUserController(e, stores.Users, stores.Devices)
	r.POST("/api/user", userAPIController.SaveUserHandler)         // handles permission checks
	r.GET("/api/user/:username", userAPIController.GetUserHandler) // handles permission checks
	r.DELETE("/api/user",
		mid.CheckPermissions(userAPIController.DeleteUserHandler,
			mid.PermsCanAny(models.DeleteUser)))

	statusAPIController := api.NewStatusController(e)
	r.GET("/api/status",
		mid.CheckPermissions(statusAPIController.GetStatus,
			mid.PermsCanAny(models.ViewDebugInfo)))

	return mid.CheckAuthAPI(r, stores.Users)
}

type rootHandler struct {
	leases stores.LeaseStore
}

func (h *rootHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if auth.IsLoggedIn(r) {
		sessionUser := models.GetUserFromContext(r)
		if sessionUser.Can(models.ViewAdminPage) {
			http.Redirect(w, r, "/admin", http.StatusTemporaryRedirect)
			return
		}

		http.Redirect(w, r, "/manage", http.StatusTemporaryRedirect)
		return
	}

	e := common.GetEnvironmentFromContext(r)
	ip := common.GetIPFromContext(r)
	reg, err := dhcp.IsRegisteredByIP(h.leases, ip)
	if err != nil {
		e.Log.WithFields(verbose.Fields{
			"error":   err,
			"package": "routes",
			"ip":      ip.String(),
		}).Error("Error getting registration status")
		http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
		return
	}

	if reg {
		http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
		return
	}

	http.Redirect(w, r, "/register", http.StatusTemporaryRedirect)
}

func notFoundHandler(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/api") {
		common.NewEmptyAPIResponse().WriteResponse(w, http.StatusNotFound)
		return
	}
	http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
}
