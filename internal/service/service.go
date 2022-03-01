package service

import (
	"flag"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	c "github.com/pvik/ncml/internal/config"

	log "github.com/sirupsen/logrus"
)

var (
	logFileHandle *os.File
)

// InitService initialize the microservice
// It does the following:
//   - initialize config file (passed in as command line arg)
//   - Setup Logging
func InitService() {
	var confFile string
	flag.StringVar(&confFile, "conf", "", "config file for microservice")

	flag.Parse()

	if confFile == "" {
		log.Fatal("Please provide config file as command line arg")
		flag.PrintDefaults()
		os.Exit(10)
	}

	c.InitConfig(confFile)

	_, serviceName := filepath.Split(os.Args[0])

	// Initialize Logfile
	if c.AppConf.Log.Format == "json" {
		log.SetFormatter(&log.JSONFormatter{})
	} else {
		// Default to TextFormatter
		log.SetFormatter(&log.TextFormatter{})
	}

	if c.AppConf.Log.Output == "file" {
		var err error
		logFile := path.Join(c.AppConf.Log.Dir,
			fmt.Sprintf("%s.log",
				serviceName))
		logFileHandle, err = os.OpenFile(logFile,
			os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
		if err != nil {
			log.WithFields(log.Fields{
				"file":  logFile,
				"error": err,
			}).Fatal("unable to open file")
		}
		log.WithFields(log.Fields{
			"file": logFile,
		}).Info("switching log output to file")
		log.SetOutput(logFileHandle)
	}

	// set log level
	switch strings.ToLower(c.AppConf.Log.Level) {
	case "trace":
		log.SetLevel(log.TraceLevel)
	case "debug":
		log.SetLevel(log.DebugLevel)
	case "info":
		log.SetLevel(log.InfoLevel)
	case "warn":
		log.SetLevel(log.WarnLevel)
	case "error":
		log.SetLevel(log.ErrorLevel)
	case "fatal":
		log.SetLevel(log.FatalLevel)
	case "panic":
		log.SetLevel(log.PanicLevel)
	}

	log.Info(serviceName + " service initialized")
}

// Shutdown closes any open files or pipes the microservice started
func Shutdown() {

	if logFileHandle != nil {
		// Revert logging back to StdOut
		log.SetOutput(os.Stdout)
		logFileHandle.Close()
	}
}
