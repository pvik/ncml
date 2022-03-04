package db

import (
	"fmt"

	"github.com/jinzhu/gorm"

	// blank import for postgres gorm dialect
	_ "github.com/jinzhu/gorm/dialects/postgres"
	log "github.com/sirupsen/logrus"
)

// DB is a GORM Database object that can be used through the
// rest of the application
var DB *gorm.DB

// Init initializes a database connection and sets up package global DB var
// to be usable through the rest of the application
func Init(host string, port int, sslmode bool, dbname string, user string, password string) {
	var err error

	var extraParamStr string
	if !sslmode {
		extraParamStr = " sslmode=disable"
	}

	DB, err = gorm.Open("postgres",
		fmt.Sprintf("host=%s port=%d user=%s dbname=%s password=%s%s",
			host, port, user, dbname, password, extraParamStr))

	if err != nil {
		log.WithFields(log.Fields{
			"host":     host,
			"port":     port,
			"dbname":   dbname,
			"user":     user,
			"password": "***",
			"error":    err,
		}).Fatal("Unable to open database")
		panic(err)
	}

	// migrate models
	DB.AutoMigrate(&Payload{})
}

// Close closes the database connection held in package global DB var
func Close() {
	DB.Close()
}
