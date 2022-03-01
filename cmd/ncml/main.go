package main

import (
	"net/http"
	"strconv"
	"time"

	c "github.com/pvik/ncml/internal/config"
	"github.com/pvik/ncml/internal/service"

	log "github.com/sirupsen/logrus"
)

func init() {
	// Initialize config file
	// Connect to DB & setup ORM
	// Setup Logging
	service.InitService()
}

func main() {
	defer service.Shutdown()

	log.Infof("Listening on %d", c.AppConf.Port)
	router := routes()

	server := &http.Server{
		Addr:         ":" + strconv.Itoa(c.AppConf.Port),
		Handler:      router,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	err := server.ListenAndServe()
	if err != nil {
		log.WithFields(log.Fields{
			"err": err,
		}).Panic("Error setting up http listener")
	}
}
