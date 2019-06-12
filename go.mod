module github.com/packet-guardian/packet-guardian

replace github.com/gorilla/sessions v1.1.3 => github.com/packet-guardian/sessions v1.1.2

require (
	bitbucket.org/ckvist/twilio v0.0.0-20170512072134-13c593a1721b
	github.com/BurntSushi/toml v0.3.1
	github.com/DATA-DOG/go-sqlmock v1.3.0
	github.com/dchest/captcha v0.0.0-20170622155422-6a29415a8364
	github.com/elazarl/go-bindata-assetfs v1.0.0
	github.com/go-sql-driver/mysql v1.4.1
	github.com/gofrs/uuid v3.2.0+incompatible
	github.com/gorilla/context v1.1.1
	github.com/gorilla/securecookie v1.1.1
	github.com/gorilla/sessions v1.1.3
	github.com/julienschmidt/httprouter v1.2.0
	github.com/lfkeitel/go-ldap-client v1.0.0
	github.com/lfkeitel/verbose/v4 v4.0.1
	github.com/oec/goradius v0.0.0-20151001122308-dce7f6ef2e5a
	github.com/packet-guardian/cas-auth v1.0.1
	github.com/packet-guardian/dhcp-lib v1.3.1-0.20190104170538-6e6243d987ae
	github.com/packet-guardian/useragent v0.0.0-20181215171402-b01a15b7aeb8
	golang.org/x/crypto v0.0.0-20190102171810-8d7daa0c54b3
	google.golang.org/appengine v1.4.0 // indirect
	gopkg.in/alexcesaro/quotedprintable.v3 v3.0.0-20150716171945-2caba252f4dc // indirect
	gopkg.in/ldap.v2 v2.5.1
	gopkg.in/mail.v2 v2.3.1
	gopkg.in/tylerb/graceful.v1 v1.2.15
)
