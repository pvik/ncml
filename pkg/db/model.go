package db

import (
	"github.com/jinzhu/gorm"
)

type ScriptStatus string

const Completed ScriptStatus = "completed"
const Running ScriptStatus = "running"
const Pending ScriptStatus = "pending"
const Error ScriptStatus = "error"

type Payload struct {
	gorm.Model
	CredentialSet string       `json:"credential-set"`
	Script        string       `json:"script"`
	Host          string       `json:"host"`
	Status        ScriptStatus `json:"status"`
	Error         string       `json:"error,omitempty"`
	Result        string       `json:",omitempty" gorm:"-"`
}
