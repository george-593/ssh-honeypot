package main

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"time"

	"github.com/george-593/ssh-honeypot/internal/event"
	"github.com/george-593/ssh-honeypot/internal/storage"
	"golang.org/x/crypto/ssh"
)

const port string = "22229"

type Handler struct {
	logger  *slog.Logger
	storage storage.Storage
}

func main() {
	// Setup Logger and Storage
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	storage, err := storage.NewJSONLogger("data/events.log")
	if err != nil {
		logger.Error("Unable to initialize storage", "error", err)
	}
	defer storage.Close()

	handler := &Handler{
		logger:  logger,
		storage: storage,
	}

	// Load host key
	key, err := os.ReadFile("host_key")
	if err != nil {
		logger.Error("Unable to load private key", "error", err)
	}

	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		logger.Error("Unable to parse private key", "error", err)
	}

	// Setup SSH Server
	config := &ssh.ServerConfig{
		PasswordCallback: handler.handlePasswordCallback,
	}
	config.AddHostKey(signer)

	// Listen for TCP Connections
	listener, err := net.Listen("tcp", "0.0.0.0:"+port)
	if err != nil {
		logger.Error("Unable to create TCP listener", "error", err)
	}

	for {
		tcpConn, err := listener.Accept()
		if err != nil {
			logger.Error("Error accepting incoming connection", "error", err)
		}
		go handleConn(tcpConn, config)
	}
}

func (h *Handler) handlePasswordCallback(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
	host, port, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		h.logger.Error("Error splitting host and port", "error", err)
	}
	e := event.Event{
		NodeID:        "honeypot-1",
		Timestamp:     time.Now(),
		SourceIP:      host,
		SourcePort:    port,
		Username:      conn.User(),
		Password:      string(password),
		ClientVersion: string(conn.ClientVersion()),
		SessionID:     fmt.Sprintf("%x", conn.SessionID()),
		Country:       "Unknown", // TODO: Implement GeoIP lookup
		ASN:           "Unknown", // TODO: Implement ASN lookup
	}
	h.storage.Store(e)
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
