package main

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/mattermost/mattermost-server/v5/plugin"
)

// nextcloud integration plugin
type Plugin struct {
	plugin.MattermostPlugin

	// configuration
	configuration     *configuration
	configurationLock sync.RWMutex

	// http router
	router *mux.Router

	// login storage
	logins     map[string]LoginData
	loginsLock sync.RWMutex
}

// login data structures
type LoginRequestData struct {
	AuthToken string `json:"auth_token"`
	UserID    string `json:"user_id"`
	Secret    string `json:"secret"`
}

type LoginData struct {
	AuthToken string
	UserID    string
	Expires   time.Time
}

// create new plugin
func NewPlugin() *Plugin {
	// create plugin
	p := &Plugin{router: mux.NewRouter()}

	// set logins
	p.logins = map[string]LoginData{}

	// configure put login route
	p.router.
		Handle("/login", p.secretAuthMiddleware(
			http.HandlerFunc(p.putLoginHandler)),
		).
		Methods("PUT")

	// configure get login route
	p.router.
		HandleFunc("/login/{token:[0-9a-f]+}", p.getLoginHandler).
		Methods("GET")

	// return plugin
	return p
}

// pass http requests to the router
func (p *Plugin) ServeHTTP(c *plugin.Context, w http.ResponseWriter, r *http.Request) {
	p.router.ServeHTTP(w, r)
}

// secret based authentication middleware
func (p *Plugin) secretAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// read body and restore it for handler
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		err = r.Body.Close()
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		r.Body = ioutil.NopCloser(bytes.NewBuffer(body))

		// decode body
		reqData := LoginRequestData{}
		err = json.Unmarshal(body, &reqData)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// abort if secret missing
		if reqData.Secret == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// load configuration
		secret := p.getConfiguration().Secret

		// abort if secret not yet set or if secrets mismatch
		if secret == "" || reqData.Secret != secret {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// carry on with the next handler
		next.ServeHTTP(w, r)
	})
}

// put login handler
func (p *Plugin) putLoginHandler(w http.ResponseWriter, r *http.Request) {
	// get request data
	reqData := LoginRequestData{}
	err := json.NewDecoder(r.Body).Decode(&reqData)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// check data existence
	if reqData.AuthToken == "" || reqData.UserID == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// create login data
	duration, _ := time.ParseDuration("30s")
	loginData := LoginData{
		AuthToken: reqData.AuthToken,
		UserID:    reqData.UserID,
		Expires:   time.Now().Add(duration),
	}

	// generate token
	token, err := generateToken(64)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// store login
	p.loginsLock.Lock()
	p.logins[token] = loginData
	p.loginsLock.Unlock()

	// respond with json
	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(map[string]string{"token": token})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

// get login handler
func (p *Plugin) getLoginHandler(w http.ResponseWriter, r *http.Request) {
	// get token and path
	token := mux.Vars(r)["token"]
	path := r.URL.Query().Get("path")
	if path == "" {
		path = "/"
	}

	// get site url
	cookiePath := "/"
	siteURL := p.API.GetConfig().ServiceSettings.SiteURL
	if siteURL != nil && *siteURL != "" {
		// Extract path from url
		parsedURL, err := url.Parse(*siteURL)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		cookiePath = parsedURL.Path
		if !strings.HasSuffix(cookiePath, "/") {
			cookiePath += "/"
		}
	}

	// Lock logins
	p.loginsLock.Lock()
	defer p.loginsLock.Unlock()

	// remove expired logins
	for token, login := range p.logins {
		if time.Now().After(login.Expires) {
			delete(p.logins, token)
		}
	}

	// get login data
	loginData, exists := p.logins[token]
	if exists {
		// Invalidate login
		delete(p.logins, token)

		// Set response cookies
		http.SetCookie(w, &http.Cookie{
			Name:  "MMAUTHTOKEN",
			Value: loginData.AuthToken,
			Path:  cookiePath,
		})
		http.SetCookie(w, &http.Cookie{
			Name:  "MMUSERID",
			Value: loginData.UserID,
			Path:  cookiePath,
		})

		// Redirect to specified path
		http.Redirect(w, r, path, http.StatusFound)
	} else {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprintln(w, "<h1><center>Login failed, please reload!</center></h1>")
	}
}

// Create random token
func generateToken(length int) (string, error) {
	bts := make([]byte, length/2)
	_, err := rand.Read(bts)
	return fmt.Sprintf("%0*x", length, bts), err
}
