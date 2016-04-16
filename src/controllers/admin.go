package controllers

import (
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/gorilla/mux"
	"github.com/onesimus-systems/packet-guardian/src/common"
	"github.com/onesimus-systems/packet-guardian/src/dhcp"
	"github.com/onesimus-systems/packet-guardian/src/models"
	"github.com/onesimus-systems/packet-guardian/src/server/middleware"
)

type Admin struct {
	e *common.Environment
}

func NewAdminController(e *common.Environment) *Admin {
	return &Admin{e: e}
}

func (a *Admin) RegisterRoutes(r *mux.Router) {
	r.HandleFunc("/admin", middleware.CheckAdmin(a.e, a.adminHomeHandler)).Methods("GET")
	r.HandleFunc("/admin/search", middleware.CheckAdmin(a.e, a.adminSearchHandler)).Methods("GET")

	r.HandleFunc("/admin/users", middleware.CheckAdmin(a.e, a.adminUserHandler)).Methods("GET", "POST")
	r.HandleFunc("/admin/users/{username}", middleware.CheckAdmin(a.e, a.adminUserHandler)).Methods("GET", "POST", "DELETE")

	r.HandleFunc("/admin/blacklist", middleware.CheckAdminAPI(a.e, a.adminBlacklistHandler)).Methods("POST", "DELETE")
	r.HandleFunc("/admin/blacklist/{username}", middleware.CheckAdminAPI(a.e, a.adminBlacklistHandler)).Methods("POST", "DELETE")
	r.HandleFunc("/admin/blacklist/{username}/all", middleware.CheckAdminAPI(a.e, a.adminBlacklistHandler)).Methods("POST", "DELETE")
}

func (a *Admin) adminHomeHandler(w http.ResponseWriter, r *http.Request) {
	data := struct{ FlashMessage string }{}
	if err := a.e.Views.NewView("admin-dash").Render(w, data); err != nil {
		a.e.Log.Error(err.Error())
	}
}

func (a *Admin) adminSearchHandler(w http.ResponseWriter, r *http.Request) {
	// Was a search query performed
	query := r.FormValue("q")
	var results []dhcp.Device
	q := dhcp.Query{}
	if query == "*" {
		q.User = ""
	} else if query != "" {
		if m, err := common.FormatMacAddress(query); err == nil {
			q.MAC = m
		} else if ip := net.ParseIP(query); ip != nil {
			q.IP = ip
		} else {
			q.User = query
		}
	}

	if query != "" {
		results = q.Search(a.e)
	}

	noResultType := ""
	if query != "" && len(results) == 0 {
		if q.User != "" {
			noResultType = "username"
		} else if q.MAC != nil {
			noResultType = "mac"
		} else if q.IP != nil {
			noResultType = "ip"
		}
	}

	data := struct {
		Query         string
		SearchResults []*models.Device
		FlashMessage  string
		NoResultType  string
	}{
		Query:         query,
		SearchResults: results,
		NoResultType:  noResultType,
	}
	if err := a.e.Views.NewView("admin-search").Render(w, data); err != nil {
		a.e.Log.Error(err.Error())
	}
}

func (a *Admin) adminBlacklistHandler(w http.ResponseWriter, r *http.Request) {
	// Slice of MAC addresses
	var black []interface{}

	if r.FormValue("devices") != "" {
		deviceIDs := strings.Split(r.FormValue("devices"), ",")
		// Need to convert strings to int for database search
		ids := make([]int, len(deviceIDs))
		for i := range deviceIDs {
			in, _ := strconv.Atoi(deviceIDs[i])
			ids[i] = in
		}

		devices := dhcp.Query{ID: ids}.Search(a.e)
		for i := range devices {
			black = append(black, devices[i].MAC)
		}
	} else {
		username, ok := mux.Vars(r)["username"]
		if !ok {
			common.NewAPIResponse(common.APIStatusGenericError, "No username given", nil).WriteTo(w)
			return
		}
		black = append(black, username)

		splitPath := strings.Split(r.URL.Path, "/")
		if splitPath[len(splitPath)-1] == "all" {
			results := dhcp.Query{User: username}.Search(a.e)
			for _, r := range results {
				black = append(black, r.MAC)
			}
		}
	}

	if r.Method == "DELETE" {
		err := dhcp.RemoveFromBlacklist(a.e.DB, black...)
		if err != nil {
			a.e.Log.Errorf("Error removing from blacklist: %s", err.Error())
			common.NewAPIResponse(common.APIStatusGenericError, "Error removing from blacklist", nil).WriteTo(w)
			return
		}
		for _, d := range black {
			a.e.Log.Infof("Removed user/MAC %s from blacklist", d)
		}
		common.NewAPIOK("Unblacklisting successful", nil).WriteTo(w)
	} else {
		err := dhcp.AddToBlacklist(a.e.DB, black...)
		if err != nil {
			a.e.Log.Errorf("Error blacklisting: %s", err.Error())
			common.NewAPIResponse(common.APIStatusGenericError, "Error blacklisting", nil).WriteTo(w)
			return
		}
		for _, d := range black {
			a.e.Log.Infof("Blacklisted user/MAC %s", d)
		}
		common.NewAPIOK("Blacklisting successful", nil).WriteTo(w)
	}
}

func (a *Admin) adminUserHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		a.saveUserHandler(w, r)
		return
	} else if r.Method == "DELETE" {
		a.deleteUserHandler(w, r)
		return
	}

	data := struct {
		Query        string
		Users        []*models.User
		FlashMessage string
	}{}

	username := mux.Vars(r)["username"]
	var template string
	if username == "" {
		users, err := models.GetAllUsers(a.e)
		if err != nil {
			a.e.Log.Errorf("Error getting users: %s", err.Error())
			data.FlashMessage = "Error getting users"
		}
		data.Users = users
		template = "admin-users"
	} else {
		user, _ := models.GetUserByUsername(a.e, username)
		if user.ID == 0 {
			user.Username = username
		}
		data.Users = []*models.User{user}
		template = "admin-user"
	}

	if err := a.e.Views.NewView(template).Render(w, data); err != nil {
		a.e.Log.Error(err.Error())
	}
}

func (a *Admin) saveUserHandler(w http.ResponseWriter, r *http.Request) {
	// username := r.FormValue("username")
	// // Get or create user
	// user, _ := models.GetUserByUsername(a.e, username)
	// if user == nil {
	// 	a.e.Log.Info("Creating user")
	// 	user = &models.User{
	// 		ID:       common.ConvertToInt(r.FormValue("user-id")),
	// 		Username: username,
	// 	}
	// }
	//
	// // Password
	// user.ClearPassword = (r.FormValue("clear-pass") == "true")
	// if r.FormValue("password") != "" {
	// 	user.NewPassword(r.FormValue("password"))
	// }
	//
	// // Registered device limit
	// limitType := r.FormValue("special-limit")
	// if limitType == "global" {
	// 	user.DeviceLimit = -1
	// } else if limitType == "unlimited" {
	// 	user.DeviceLimit = 0
	// } else {
	// 	user.DeviceLimit = common.ConvertToInt(r.FormValue("device-limit"))
	// }
	//
	// // Expiration times
	// loc, _ := time.LoadLocation("Local")
	// if r.FormValue("device-expiration") == "0" || r.FormValue("device-expiration") == "" {
	// 	user.DefaultExpiration = time.Unix(0, 0)
	// } else if r.FormValue("device-expiration") == "1" {
	// 	user.DefaultExpiration = time.Unix(1, 0)
	// } else {
	// 	user.DefaultExpiration, _ = time.ParseInLocation("2006-01-02 15:04:05", r.FormValue("device-expiration"), loc)
	// }
	//
	// if r.FormValue("valid-after") == "0" || r.FormValue("valid-after") == "" {
	// 	user.ValidAfter = time.Unix(0, 0)
	// } else {
	// 	user.ValidAfter, _ = time.ParseInLocation("2006-01-02 15:04:05", r.FormValue("valid-after"), loc)
	// }
	//
	// if r.FormValue("valid-before") == "0" || r.FormValue("valid-before") == "" {
	// 	user.ValidBefore = time.Unix(0, 0)
	// } else {
	// 	user.ValidBefore, _ = time.ParseInLocation("2006-01-02 15:04:05", r.FormValue("valid-before"), loc)
	// }
	//
	// if err := user.Save(a.e.DB); err != nil {
	// 	a.e.Log.Errorf("Error saving user: %s", err.Error())
	// 	common.NewAPIResponse(common.APIStatusGenericError, "Error saving user", nil).WriteTo(w)
	// 	return
	// }
	//
	// a.e.Log.Infof("Created user augmentation: %s", user.Username)
	common.NewAPIOK("User created", nil).WriteTo(w)
}

func (a *Admin) deleteUserHandler(w http.ResponseWriter, r *http.Request) {
	// username := mux.Vars(r)["username"]
	//
	// user, err := models.GetUser(a.e.DB, username)
	// if user == nil {
	// 	a.e.Log.Errorf("Error deleting user: %s", err.Error())
	// 	common.NewAPIResponse(common.APIStatusGenericError, "Error deleting user", nil).WriteTo(w)
	// 	return
	// }
	//
	// sql := "DELETE FROM \"user\" WHERE \"username\" = ?"
	// _, err = a.e.DB.Exec(sql, username)
	// if err != nil {
	// 	a.e.Log.Errorf("Error deleting user: %s", err.Error())
	// 	common.NewAPIResponse(common.APIStatusGenericError, "Error deleting user", nil).WriteTo(w)
	// 	return
	// }
	//
	// a.e.Log.Infof("Deleted user: %s", username)
	common.NewAPIOK("User deleted", nil).WriteTo(w)
}
