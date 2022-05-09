package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/go-chi/chi"
	"github.com/go-ping/ping"
	c "github.com/pvik/ncml/internal/config"
	"github.com/pvik/ncml/pkg/db"
	"github.com/pvik/ncml/pkg/httphelper"
	log "github.com/sirupsen/logrus"
)

var ScriptExecChan = make(chan uint)

func init() {
	i := 0
	for i < c.AppConf.Workers {
		go jobWorker(i)
		i = i + 1
	}
}

func apiPing(w http.ResponseWriter, r *http.Request) {
	authHeaderArr, ok := r.Header["Authorization"]
	if !ok || len(authHeaderArr) < 1 || len(authHeaderArr[0]) < 1 {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if strings.HasPrefix(authHeaderArr[0], "Bearer ") {
		tokenString := strings.Split(authHeaderArr[0], " ")[1]

		if jwtAuth(tokenString) {
			pingHostStr := chi.URLParam(r, "pingHost")
			pinger, err := ping.NewPinger(pingHostStr)
			if err != nil {
				panic(err)
			}

			pinger.Count = 1
			pinger.Timeout = time.Duration(c.AppConf.Ping.TimeoutSec) * time.Second

			pinger.SetPrivileged(c.AppConf.Ping.Privileged) // to allow ping from docker container

			log.Debugf("Q: %+v", r.URL.Query())
			pktCount, ok := r.URL.Query()["pkts"]
			if !ok || len(pktCount) < 1 || len(pktCount[0]) < 1 {
				log.Debug("query param pkts not given")
			} else {
				pktCountInt, err := strconv.Atoi(pktCount[0])
				log.Debugf("pktCountInt: %d, err: %s", pktCountInt, err)
				if err == nil {
					pinger.Count = pktCountInt
				}
			}

			err = pinger.Run() // Blocks until finished.
			if err != nil {
				httphelper.RespondwithJSON(w, http.StatusInternalServerError, map[string]interface{}{"state": "error", "error": err})
				return
			}
			stats := pinger.Statistics() // get send/receive/duplicate/rtt stats
			log.Debugf("ping: %s stats: ", pingHostStr, stats)
			httphelper.RespondwithJSON(w, http.StatusOK, stats)
			return
		}
	}

	w.WriteHeader(http.StatusUnauthorized)
	return
}

func apiResult(w http.ResponseWriter, r *http.Request) {
	authHeaderArr, ok := r.Header["Authorization"]
	if !ok || len(authHeaderArr) < 1 || len(authHeaderArr[0]) < 1 {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if strings.HasPrefix(authHeaderArr[0], "Bearer ") {
		tokenString := strings.Split(authHeaderArr[0], " ")[1]

		if jwtAuth(tokenString) {
			payloadIDStr := chi.URLParam(r, "payloadID")
			payloadID, _ := strconv.ParseUint(payloadIDStr, 10, 64)
			payload := db.Payload{}
			res := db.DB.First(&payload, payloadID)
			if res.Error != nil {
				log.Errorf("Unable to retrieve Payload from DB: %s", res.Error)
				payload.Status = db.Error
				payload.Error = res.Error.Error()

				httphelper.RespondwithJSON(w, http.StatusInternalServerError, payload)
				return
			}

			if payload.Status == db.Completed {
				// read result file
				result, err := ioutil.ReadFile(filepath.Join(c.AppConf.ResultStoreDir, fmt.Sprintf("%d", payload.ID)))
				if err != nil {
					log.Errorf("Unable to retrieve Result from disk: %s", err)
					payload.Status = db.Error
					payload.Error = err.Error()

					httphelper.RespondwithJSON(w, http.StatusInternalServerError, payload)
					return
				}
				payload.Result = string(result)
			}

			httphelper.RespondwithJSON(w, http.StatusOK, payload)
			return
		}
	}

	w.WriteHeader(http.StatusUnauthorized)
	return
}

func apiExec(w http.ResponseWriter, r *http.Request) {
	authHeaderArr, ok := r.Header["Authorization"]
	if !ok || len(authHeaderArr) < 1 || len(authHeaderArr[0]) < 1 {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if strings.HasPrefix(authHeaderArr[0], "Bearer ") {
		tokenString := strings.Split(authHeaderArr[0], " ")[1]

		if jwtAuth(tokenString) {
			// Parse JSON Request
			log.Debug("process Inbound Exec")

			var payloadStr string
			{
				payloadBuf := new(bytes.Buffer)
				payloadBuf.ReadFrom(r.Body)
				payloadStr = payloadBuf.String()
			}

			log.Tracef("Exec Payload: %+v\n", payloadStr)

			var payload db.Payload
			err := json.Unmarshal([]byte(payloadStr), &payload)
			if err != nil {
				log.WithFields(log.Fields{
					"error": err,
				}).Error("unable to unmarshal alert data")

				payload.Error = err.Error()
				payload.Status = db.Error

				db.DB.Save(&payload)

				httphelper.RespondwithJSON(w, http.StatusInternalServerError, payload)
				return
			}

			payload.ID = 0 // Prevent creating a new job record from an ID in JSON
			payload.Status = db.Pending
			r := db.DB.Save(&payload)
			if r.Error != nil || payload.ID == 0 {
				payload.Error = err.Error()
				payload.Status = db.Error

				httphelper.RespondwithJSON(w, http.StatusInternalServerError, payload)
				return
			}

			// queue job to workers
			ScriptExecChan <- payload.ID
			httphelper.RespondwithJSON(w, http.StatusOK, payload)
			return
		}
	}

	w.WriteHeader(http.StatusUnauthorized)
	return
}

func jobWorker(workerID int) {
	log.Debugf("jobWorker (%d)", workerID)

	// recover from panic
	defer func() {
		if r := recover(); r != nil {
			log.WithFields(log.Fields{
				"workerID": workerID,
				"err":      r.(error),
			}).Error("Recovering from Panic in jobWorker")

			// restart function
			go jobWorker(workerID)
		}
	}()

	for payloadID := range ScriptExecChan {
		log.Debugf("Worker#%d: Processing Payload #%d", workerID, payloadID)

		payload := db.Payload{}
		res := db.DB.First(&payload, payloadID)
		if res.Error != nil {
			log.Errorf("Unable to retrieve Payload from DB: %s", res.Error)
		}

		payload.Status = db.Running
		db.DB.Save(&payload)

		err := sshExec(payload.Host, payload.CredentialSet, payload.Script, filepath.Join(c.AppConf.ResultStoreDir, fmt.Sprintf("%d", payload.ID)))

		if err != nil {
			payload.Status = db.Error
			payload.Error = err.Error()
		} else {
			payload.Status = db.Completed
		}

		db.DB.Save(&payload)
	}
}

func sshExec(host, credentialSetName, script, resultFileName string) error {
	// check if credntialSet exists in config
	credentialSet, credentialSetExists := c.AppConf.CredentialsMap[credentialSetName]

	if credentialSetExists {
		conf := &ssh.ClientConfig{
			User:            credentialSet.Username,
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			Auth: []ssh.AuthMethod{
				ssh.Password(credentialSet.Password),
			},
		}

		// check if port is present
		hostSplit := strings.Split(host, ":")
		if len(hostSplit) < 2 {
			host = fmt.Sprintf("%s:22", host)
		}
		var conn *ssh.Client
		conn, err := ssh.Dial("tcp", host, conf)
		if err != nil {
			log.Errorf("unable to dial: %s", err)
			return fmt.Errorf("Unable to connect to host: %s", err)
		}
		defer conn.Close()

		var session *ssh.Session
		var stdin io.WriteCloser
		var stdout, stderr io.Reader
		session, err = conn.NewSession()
		if err != nil {
			return fmt.Errorf("Unable to establish ssh session to host: %s", err)
		}
		defer session.Close()

		log.Debug("session established")
		stdin, err = session.StdinPipe()
		if err != nil {
			log.Errorf("Unable to open StdIn pipe: %s", (err.Error()))
		}

		stdout, err = session.StdoutPipe()
		if err != nil {
			log.Errorf("Unable to open StdOut pipe: %s", (err.Error()))
		}

		stderr, err = session.StderrPipe()
		if err != nil {
			log.Errorf("Unable to open StdErr pipe: %s", (err.Error()))
		}

		var sessionOutErrMsg error

		// Session StdOut
		go func() {
			log.Debug("stdOut handler")
			scanner := bufio.NewScanner(stdout)
			// save result to file
			f, err := os.Create(resultFileName)
			if err != nil {
				sessionOutErrMsg = fmt.Errorf("Unable to save result: %s", err)
				return
			}

			defer f.Close()
			defer log.Debug("stdOut handler done")

			for {
				if tkn := scanner.Scan(); tkn {
					rcv := scanner.Bytes()

					_, err = f.Write(rcv)
					f.Write([]byte("\n")) // explicit newline
					if err != nil {
						sessionOutErrMsg = fmt.Errorf("Unable to write result: %s", err)
					}
				} else {
					if scanner.Err() != nil {
						sessionOutErrMsg = fmt.Errorf("Error receiving StdOut stream from Host: %s", scanner.Err())
					} else {
						//fmt.Println("io.EOF")
					}
					return
				}
			}
		}()

		// Session StdErr
		go func() {
			log.Debug("stdErr handler")
			scanner := bufio.NewScanner(stderr)

			for scanner.Scan() {
				log.Errorf("StdErr: %s", scanner.Text())
			}
			log.Debug("stdErr handler done")
		}()

		// configure terminal mode
		modes := ssh.TerminalModes{
			ssh.ECHO: 0, // supress echo
		}
		// run terminal session
		if err := session.RequestPty("xterm", 50, 80, modes); err != nil {
			log.Errorf("unable to request pty: %s", err)
		}

		err = session.Shell()
		if err != nil {
			return fmt.Errorf("Unable to open shell on host: %s", err)
		}

		script = script + "\nexit"
		for _, l := range strings.Split(script, "\n") {
			log.Debugf("ssh run script line: %s", l)
			_, err := stdin.Write([]byte(l + "\n"))
			if err != nil {
				log.Errorf("unable to write to stdIn: %s", err)
			}
		}

		session.Wait()

		// stdin.Write([]byte("exit\n"))

		//err = session.Run(script)
		// if err != nil {
		// 	return fmt.Errorf("Unable to run script on host: %s", err)
		// }
		if sessionOutErrMsg != nil {
			return fmt.Errorf("Error Processing Std streams from host: %s", sessionOutErrMsg)
		}

		log.Debug("sshExec done")

		return nil
	} else {
		return fmt.Errorf("Invalid Credential Set")
	}
}
