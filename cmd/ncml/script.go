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

	"github.com/go-chi/chi/v5"
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
		go jobWorker(i, ScriptExecChan)
		i = i + 1
	}
}

func apiPing(w http.ResponseWriter, r *http.Request) {

	pingHostStr := chi.URLParam(r, "pingHost")
	pinger, err := ping.NewPinger(pingHostStr)
	if err != nil {
		panic(err)
	}

	pinger.Count = 1
	pinger.Timeout = time.Duration(c.AppConf.Ping.TimeoutSec) * time.Second

	pinger.SetPrivileged(c.AppConf.Ping.Privileged) // to allow ping from docker container

	//log.Debugf("Q: %+v", r.URL.Query())
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

	if pinger.Count > 5 {
		pinger.Count = 5
	}

	err = pinger.Run() // Blocks until finished.
	if err != nil {
		log.Errorf("ping error: %s", err)
		httphelper.RespondwithJSON(w, http.StatusInternalServerError, map[string]interface{}{"state": "error", "error": err})
		return
	}

	stats := pinger.Statistics() // get send/receive/duplicate/rtt stats
	log.Debugf("ping: %s stats: %+v", pingHostStr, stats)
	httphelper.RespondwithJSON(w, http.StatusOK, stats)
}

func apiResult(w http.ResponseWriter, r *http.Request) {
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
}

func apiExec(w http.ResponseWriter, r *http.Request) {
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
	rec := db.DB.Save(&payload)
	if rec.Error != nil || payload.ID == 0 {
		payload.Error = err.Error()
		payload.Status = db.Error

		httphelper.RespondwithJSON(w, http.StatusInternalServerError, payload)
		return
	}

	// queue job to workers
	go func(jobID uint, c chan<- uint) {
		c <- jobID
	}(payload.ID, ScriptExecChan)
	// ScriptExecChan <- payload.ID

	httphelper.RespondwithJSON(w, http.StatusOK, payload)
}

func jobWorker(workerID int, scriptExecChan <-chan uint) {
	log.Debugf("jobWorker (%d)", workerID)

	// recover from panic
	defer func() {
		if r := recover(); r != nil {
			log.WithFields(log.Fields{
				"workerID": workerID,
				"err":      r.(error),
			}).Error("Recovering from Panic in jobWorker")

			// restart function
			go jobWorker(workerID, scriptExecChan)
		}
	}()

	for payloadID := range scriptExecChan {
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
			Timeout: 30 * time.Second, // 30 sec max to eestablish connection
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

		linesRecvdAfterCmd := 0
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

			defer func() {
				log.Debug("stdOut handler done")
			}()

			prevLine := ""
			sameRecv := 0
			stdOutHandlerExitSent := false
			for {
				if tkn := scanner.Scan(); tkn {
					rcv := scanner.Bytes()

					if string(rcv) == prevLine {
						sameRecv = sameRecv + 1
					} else {
						sameRecv = 0
					}

					if sameRecv < 3 { // don;t write duplicate lines
						log.Debugf("StdOut (%d | %d): %s", sameRecv, linesRecvdAfterCmd, rcv)
						_, err = f.Write(rcv)
						linesRecvdAfterCmd = linesRecvdAfterCmd + 1
					}
					if err != nil {
						sessionOutErrMsg = fmt.Errorf("Unable to write result: %s", err)
					}

					if strings.TrimSpace(string(rcv)) != "" { // don't insert unnecessary newline
						f.Write([]byte("\n")) // explicit newline
					}

					prevLine = string(rcv)

					//stdin.Write([]byte("\n"))

					// if sameRecv > 6 {
					// 	stdin.Write([]byte("exit\n"))
					// }

					if strings.HasSuffix(strings.TrimSpace(string(rcv)), "exit") {
						stdOutHandlerExitSent = true
					}
				} else {
					if scanner.Err() != nil {
						log.Warnf("Error receiving StdOut stream from Host: %s", scanner.Err())
						if !stdOutHandlerExitSent {
							sessionOutErrMsg = fmt.Errorf("Error receiving StdOut stream from Host: %s", scanner.Err())
						} else {
							log.Warnf("Ignoring StdOut stream error, exit already rcv'd")
						}
					} else {
						//fmt.Println("io.EOF")
					}
					return
				}
			}
		}()

		// Session StdErr
		var stdErrMsg error
		go func() {
			log.Debug("stdErr handler")
			scanner := bufio.NewScanner(stderr)

			for scanner.Scan() {
				log.Errorf("StdErr: %s", scanner.Text())
				stdErrMsg = fmt.Errorf("%s\n%s", stdErrMsg, scanner.Text())
			}
			log.Debug("stdErr handler done")
		}()

		// configure terminal mode
		modes := ssh.TerminalModes{
			ssh.ECHO:   0, // supress echo
			ssh.ECHONL: 1,
			ssh.OCRNL:  1, // Translate carriage return to newline (output).
		}
		// run terminal session
		if err := session.RequestPty("xterm", 50, 80, modes); err != nil {
			log.Errorf("unable to request pty: %s", err)
		}

		err = session.Shell()
		if err != nil {
			return fmt.Errorf("Unable to open shell on host: %s", err)
		}

		// timeout handling
		errChannel := make(chan error, 1)
		timeout := 240 * time.Second
		go func() {

			if timeout > 0 {
				time.AfterFunc(timeout, func() {
					errChannel <- fmt.Errorf("timeout")
				})
			}

			err := <-errChannel
			if err != nil {
				log.Errorf("ssh timeout, try exit")
				stdin.Write([]byte("exit\n"))
				time.Sleep(10)

				log.Errorf("ssh timeout, closing Connection/Session")
				session.Close()
				conn.Close()
			}
			log.Debugf("ssh timeout go routine exit")
		}()

		script = fmt.Sprintf("%s\nexit\n", script)
		for _, l := range strings.Split(script, "\n") {
			log.Debugf("ssh run script line: %s", l)
			linesRecvdAfterCmd = 0
			_, err := stdin.Write([]byte(l + "\n"))
			if err != nil {
				log.Errorf("unable to write to stdIn: %s", err)
				break
			}
			stdin.Write([]byte("\n"))
			log.Debug("stdin: WAIT for prev cmd to finish before sending next cmd")

			sendNextCmd := false
			for !sendNextCmd {
				prevLinesRecvd := linesRecvdAfterCmd
				time.Sleep(time.Second * 2)
				if prevLinesRecvd == linesRecvdAfterCmd {
					sendNextCmd = true
				}
			}
		}

		log.Debug("wait for cmds to finish")
		err = session.Wait()
		if err != nil {
			return fmt.Errorf("error closing shell on host: %s", err)
		}

		errChannel <- nil

		if sessionOutErrMsg != nil {
			return fmt.Errorf("Error Processing Std streams from host: %s", sessionOutErrMsg)
		}

		log.Debug("sshExec done")

		return nil
	} else {
		return fmt.Errorf("Invalid Credential Set")
	}
}
