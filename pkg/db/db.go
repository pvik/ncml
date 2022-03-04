package db

import (
	"fmt"

	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlserver"
	"gorm.io/gorm"

	// blank import for postgres gorm dialect
	_ "github.com/jinzhu/gorm/dialects/postgres"
	log "github.com/sirupsen/logrus"
)

// DB is a GORM Database object that can be used through the
// rest of the application
var DB *gorm.DB

// Init initializes a database connection and sets up package global DB var
// to be usable through the rest of the application
func Init(dbType string, host string, port int, sslmode bool, dbname string, user string, password string) {
	var err error

	if dbType == "postgres" {
		var extraParamStr string
		if !sslmode {
			extraParamStr = " sslmode=disable"
		}

		DB, err = gorm.Open(postgres.Open(
			fmt.Sprintf("host=%s port=%d user=%s dbname=%s password=%s%s",
				host, port, user, dbname, password, extraParamStr)),
			&gorm.Config{})

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
	} else if dbType == "sqlserver" {
		DB, err = gorm.Open(sqlserver.Open(
			fmt.Sprintf("sqlserver://%s:%s@%s:%d?database=%s",
				user, password, host, port, dbname)),
			&gorm.Config{})

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
	} else {
		panic(fmt.Errorf("Invalid DB type"))
	}

	// migrate models
	DB.AutoMigrate(&Payload{})
}

// Close closes the database connection held in package global DB var
func Close() {
	//	DB.Close()
}
