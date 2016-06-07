package middleware

import (
	"net"
	"net/http"
	"strings"

	"github.com/onesimus-systems/packet-guardian/src/common"
	"github.com/onesimus-systems/packet-guardian/src/models"
)

func CheckReg(e *common.Environment, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := net.ParseIP(strings.Split(r.RemoteAddr, ":")[0])
		reg, err := models.IsRegisteredByIP(e, ip)
		if err != nil {
			e.Log.WithField("Err", err).Error("Couldn't get registration status")
		}

		if reg {
			data := map[string]interface{}{
				"msg":   "This device is already registered",
				"error": true,
			}
			e.Views.NewView("register-guest-msg", r).Render(w, data)
			return
		}

		next.ServeHTTP(w, r)
	})
}
