package main

import (
	"context"
	"html/template"
	"net/http"
	"strings"
	"time"

	c "github.com/pvik/ncml/internal/config"
	"github.com/pvik/ncml/pkg/httphelper"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/tdewolff/minify/v2"

	log "github.com/sirupsen/logrus"
)

type webContextKey string

const claimsContextKey webContextKey = "jwtClaims"

var templateRoot string
var m *minify.M
var tmplFuncMap template.FuncMap

func init() {
	log.Println("Initializing HTTP ReST API Routes")
}

func routes() *chi.Mux {
	r := chi.NewRouter()

	// define middleware stack
	r.Use(middleware.Logger)
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)

	// Set a timeout value on the request context (ctx), that will signal
	// through ctx.Done() that the request has timed out and further
	// processing should be stopped.
	r.Use(middleware.Timeout(time.Duration(c.AppConf.HTTPTimeoutSec-1) * time.Second))

	r.Route("/ncml/v1", func(r1 chi.Router) {
		r1.Use(authApiHandler)

		r1.Post("/execute", apiExec)
		r1.Get("/result/{payloadID:[0-9]+}", apiResult)
		r1.Get("/ping/{pingHost}", apiPing)
	})

	return r
}

func authApiHandler(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {

		authHeaderArr, ok := r.Header["Authorization"]
		if !ok || len(authHeaderArr) < 1 || len(authHeaderArr[0]) < 1 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		if strings.HasPrefix(authHeaderArr[0], "Bearer ") {
			tokenString := strings.Split(authHeaderArr[0], " ")[1]

			auth, claims := jwtAuth(tokenString)
			if auth {
				ctx := context.WithValue(r.Context(), claimsContextKey, claims)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}
		}

		httphelper.RespondWithError(w, http.StatusUnauthorized,
			"Unauthorized", "Invalid API Key")
		return

	}

	return http.HandlerFunc(fn)
}
