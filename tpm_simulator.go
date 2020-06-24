// +build test linux

/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tpmprovider

import (
	"fmt"
	"io/ioutil"
	"os/exec"
	"testing"
	"strings"
	"strconv"
	"time"
)

const (
	TPM2_ABRMD = "tpm2-abrmd"
	TPM_SERVER = "tpm_server"
	DEFAULT_SLEEP_MILLISECONDS = 500 * time.Millisecond
	MAX_ATTEMPTS = 5
)

//
// The TpmSimulator wraps the tpm2-abrmd service and the MS simulator (installed 
// at /simulator on 'gta-devel' container).  The container has tpm2-abrmd.service
// file configured to use "mssim" so that communicates with the simulator instead
// of the physical TPM device (so that unit tests can be integrated into cicd 
// pipelines).
//
// Manually, you would run '/simulator/src/tpm_server -rm&' to start the simulator
// in the background and then start tpm2-abrmd ('systemctl start tpm2-abrmd').  'rm'
// removes the NVChip file so that the simulator is reset each time.
//
// This class attempts to automate that process with some duck-tape and bubble-gum
// in place (i.e. time.Sleep) to make it work.  Sleeps are required to make sure
// the simulator is initiated before starting tpm2-abrmd, to make sure tpm2-abrmd
// is initiated before a new tpmprovider instance is created, etc.  In a nutshell,
// the unit tests may execute slower but that is better than intermittent failures
// caused by initiation issues.
//
type TpmSimulator struct {
	simulatorCmd *exec.Cmd
	t *testing.T
}

var instance *TpmSimulator

func GetTpmSimulator(t *testing.T) *TpmSimulator {

	if t == nil {
		panic("'t' cannot be nil")
	}

	if instance == nil {
		t.Log("Initializing simulator...")
		simulator := TpmSimulator{}
		simulator.t = t
		instance = &simulator
	}

	return instance
}

func (simulator *TpmSimulator) isRunning() bool {
	running := false

	return running
}

func (simulator *TpmSimulator) Start() error {
	if simulator.isRunning() {
		simulator.Stop()
	}

	err := simulator.startSimulator()
	if err != nil {
		simulator.t.Fatal(err)
	}
	
	err = simulator.startTpm2Abrmd()
	if err != nil {
		simulator.t.Fatal(err)
	}
	
	return nil
}

func (simulator *TpmSimulator) Stop() error {

	err := simulator.stopTpm2Abrmd()
	if err != nil {
		simulator.t.Fatal(err)
	}
	
	err = simulator.stopSimulator()
	if err != nil {
		simulator.t.Fatal(err)
	}

	return nil
}

func (simulator *TpmSimulator) startTpm2Abrmd() error {
	pid := getPidByName(TPM2_ABRMD)
	if pid > 0 {
		simulator.stopTpm2Abrmd()
	}

	err := exec.Command("systemctl", "start", TPM2_ABRMD).Run()
	if err != nil {
		fmt.Printf("There was an error starting the tpm2-abrmd: %s\n", err)
		return err
	}

	// add some sleep to make sure tpm2-abrmd is initialized before
	// the unit test tries to create a new instance of the tpm-provider
	time.Sleep(DEFAULT_SLEEP_MILLISECONDS*4)
	return nil
}

func (simulator *TpmSimulator) startSimulator() error {

	if(simulator.simulatorCmd != nil) {
		simulator.stopSimulator()
	}

	simulator.simulatorCmd = exec.Command("/simulator/src/tpm_server", "-rm")
	err := simulator.simulatorCmd.Start()	// keep it running in the backgournd
	if err != nil {
		simulator.t.Logf("There was an error starting the tpm_server: %s\n", err)
		return err
	}

	// appears to be a race condition where tpm2-abrmd is started but the
	// simulator is not all the way up -- sleep for now...
	time.Sleep(DEFAULT_SLEEP_MILLISECONDS*4)
	simulator.t.Logf("TPM Simulator started: %d\n", simulator.simulatorCmd.Process.Pid)

	return nil
}

func (simulator *TpmSimulator) stopTpm2Abrmd() error {
	attempts := 0
	for {
		_ = exec.Command("systemctl", "stop", TPM2_ABRMD).Run()

		pid := getPidByName(TPM2_ABRMD)
		if pid == 0 {
			break
		}

		if attempts >= MAX_ATTEMPTS {
			return fmt.Errorf("Failed to stop %s after %d attempts\n", TPM2_ABRMD, MAX_ATTEMPTS)
		}

		attempts += 1
		fmt.Printf("Waiting for '%s' service [PID:%d] to stop, attempt %d of %d\n", TPM2_ABRMD, pid, attempts, MAX_ATTEMPTS)
		time.Sleep(DEFAULT_SLEEP_MILLISECONDS*2)
	}

	return nil
}

func (simulator *TpmSimulator) stopSimulator() error {

	if simulator.simulatorCmd != nil{
		simulator.simulatorCmd.Process.Kill()
		simulator.simulatorCmd = nil
		time.Sleep(DEFAULT_SLEEP_MILLISECONDS*2)
	}

	return nil
}

// returns zero if not found, >0 if found
func getPidByName(processName string) int {

	cmd := exec.Command("pgrep", processName)
	out, err := cmd.StdoutPipe()
	if err != nil {
		return 0
	}

	err = cmd.Start()
	if err != nil {
		return 0
	}

	b, _ := ioutil.ReadAll(out)

	err = cmd.Wait()
	if err != nil {
		return 0
	}

	pid := 0
	if len(b) > 0 {
		pidString := string(b)
		pidString = strings.Replace(pidString, "\n", "", -1)
		pid, err = strconv.Atoi(pidString)
		if err != nil {
			fmt.Printf("error: could not parse pid from '%s'", pidString)
		}
	}

	return pid
}

func serviceIsRunning(serviceName string) bool {

	cmd := exec.Command("systemctl", "is-active", serviceName)

	err := cmd.Run()
	if err != nil {
		return false
	}

	return true
}
