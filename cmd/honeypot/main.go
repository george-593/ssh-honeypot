package main

import (
	"fmt"
	"log"
	"net"
	"os"

	"golang.org/x/crypto/ssh"
)

const port string = "22229"

func main() {
	// Load host key
	key, err := os.ReadFile("host_key")
	if err != nil {
		log.Fatalf("Unable to load private key: %s", err)
	}

	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		log.Fatalf("Unable to parse private key: %s", err)
	}

	// Setup SSH Server
	config := &ssh.ServerConfig{
		PasswordCallback: handlePasswordCallback,
	}
	config.AddHostKey(signer)

	// Listen for TCP Connections
	listener, err := net.Listen("tcp", "0.0.0.0:"+port)
	if err != nil {
		log.Fatalf("Unable to create TCP listener: %s", err)
	}

	for {
		tcpConn, err := listener.Accept()
		if err != nil {
			log.Printf("Error accepting incoming connection: %s", err)
		}
		go handleConn(tcpConn, config)
	}
}

func handlePasswordCallback(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
	log.Printf("Login Attempt: User:%s Password:%s From:%s", conn.User(), string(password), conn.RemoteAddr())
	return nil, fmt.Errorf("Rejected")
}

func handleConn(tcpConn net.Conn, config *ssh.ServerConfig) {
	_, chans, reqs, err := ssh.NewServerConn(tcpConn, config)
	if err != nil {
		return
	}

	// Cleanup connection
	go ssh.DiscardRequests(reqs)
	go func() {
		for newChan := range chans {
			newChan.Reject(ssh.Prohibited, "not allowed")
		}
	}()
}
