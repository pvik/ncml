package main

import (
	"html/template"
	"time"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/tdewolff/minify/v2"

	log "github.com/sirupsen/logrus"
)

// var router *chi.Mux

var templateRoot string
var m *minify.M
var tmplFuncMap template.FuncMap

func init() {
	log.Println("Initializing HTTP ReST API Routes")
}

func routes() *chi.Mux {
	r := chi.NewRouter()

	// define middleware stack
	r.Use(middleware.Recoverer)

	// Set a timeout value on the request context (ctx), that will signal
	// through ctx.Done() that the request has timed out and further
	// processing should be stopped.
	r.Use(middleware.Timeout(30 * time.Second))

	r.Use(middleware.DefaultLogger)

	r.Route("/ncml/v1", func(r1 chi.Router) {
		// r1.Get("/jwt", apiJWT)
		// r1.Get("/auth", apiAuth)
	})

	return r
}
