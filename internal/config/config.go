package config

import (
	"fmt"

	"github.com/BurntSushi/toml"
	log "github.com/sirupsen/logrus"
)

// LogConfig holds log information
type LogConfig struct {
	Format string `toml:"format"`
	Output string `toml:"output"`
	Dir    string `toml:"log-directory"`
	Level  string `toml:"level"`
}

// DBConfig holds connection details to a Database for storing
// payload details, etc
type DBConfig struct {
	Host     string `toml:"host"`
	Port     int    `toml:"port"`
	SSLMode  bool   `toml:"sslmode"`
	Username string `toml:"username"`
	Password string `toml:"password"`
	DBName   string `toml:"dbname"`
}

type JWTConfig struct {
	Format bool   `toml:"enabled"`
	Secret string `toml:"secret"`
}

type CredentialSet struct {
	Username string `toml:"username"`
	Password string `toml:"password"`
}

// Config holds all the details from config.toml passed to application
type Config struct {
	Port           int                      `toml:"port"`
	Workers        int                      `toml:"workers"`
	ResultStoreDir string                   `toml:"result-store-dir"`
	JWTConfig      JWTConfig                `toml:"jwt-auth"`
	CredentialsMap map[string]CredentialSet `toml:"credentials"`
	DBConfig       DBConfig                 `toml:"db"`
	Log            LogConfig                `toml:"log"`
}

// AppConf package global has values parsed from config.toml
var AppConf Config

// InitConfig Initializes AppConf
// It reads in the Config file at configPath and populates AppConf
func InitConfig(configPath string) {
	log.WithFields(log.Fields{
		"file": configPath,
	}).Info("Reading in Config File")

	if _, err := toml.DecodeFile(configPath, &AppConf); err != nil {
		log.WithFields(log.Fields{
			"error": err,
		}).Error("unable to parse config toml file")
		panic(fmt.Errorf("unable to parse config toml file"))
	}

	log.Infof("Config: %+v", AppConf)
}
