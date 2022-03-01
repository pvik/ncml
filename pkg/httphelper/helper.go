package httphelper

import (
	"bytes"
	"encoding/json"
	"net/http"

	log "github.com/sirupsen/logrus"
)

func RequestBodyString(r *http.Request) string {
	var reqBodyStr string
	{
		reqBodyBuf := new(bytes.Buffer)
		reqBodyBuf.ReadFrom(r.Body)
		reqBodyStr = reqBodyBuf.String()
	}
	return reqBodyStr
}

// RespondWithError return error message
func RespondWithError(w http.ResponseWriter, code int, msg string, detail string) {
	RespondwithJSON(w, code,
		map[string]string{
			"status":  "fail",
			"message": msg,
			"detail":  detail,
		})
}

// RespondwithJSON write json response format
func RespondwithJSON(w http.ResponseWriter, code int, payload interface{}) {
	response, _ := json.Marshal(payload)

	log.WithFields(log.Fields{
		"payload": payload,
	}).Info("http response")

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(response)
}
