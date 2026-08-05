package main

import (
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"time"

	"github.com/george-593/ssh-honeypot/internal/event"
	"github.com/george-593/ssh-honeypot/internal/storage"
	"github.com/oschwald/geoip2-golang/v2"
	"golang.org/x/crypto/ssh"
)

const port string = "22"

type Handler struct {
	logger    *slog.Logger
	storage   storage.Storage
	nodeID    string
	countryDB *geoip2.Reader
	asnDB     *geoip2.Reader
}

func main() {
	// Setup Logger and Storage
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	storage, err := storage.NewSQLiteStorage("data/events.sql")
	if err != nil {
		logger.Error("Unable to initialize storage", "error", err)
		os.Exit(1)
	}
	defer storage.Close()

	// Load node ID
	nodeID := os.Getenv("NODE_ID")
	if nodeID == "" {
		nodeID, _ = os.Hostname()
		logger.Warn("Unable to load NODE_ID from env, resorting to hostname", "hostname", nodeID)
	}

	// Load Coutry and ASN DB
	countryDB, err := geoip2.Open("data/GeoLite2-Country.mmdb")
	if err != nil {
		logger.Error("Unable to load Country DB", "error", err)
		os.Exit(1)
	}
	defer countryDB.Close()

	asnDB, err := geoip2.Open("data/GeoLite2-ASN.mmdb")
	if err != nil {
		logger.Error("Unable to load ASN DB", "error", err)
		os.Exit(1)
	}
	defer asnDB.Close()

	handler := &Handler{
		logger:    logger,
		storage:   storage,
		nodeID:    nodeID,
		countryDB: countryDB,
		asnDB:     asnDB,
	}

	// Load host key
	key, err := os.ReadFile("host_key")
	if err != nil {
		logger.Error("Unable to load private key", "error", err)
		os.Exit(1)
	}

	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		logger.Error("Unable to parse private key", "error", err)
		os.Exit(1)
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
		os.Exit(1)
	}

	for {
		tcpConn, err := listener.Accept()
		if err != nil {
			logger.Error("Error accepting incoming connection", "error", err)
			continue
		}
		go handleConn(tcpConn, config)
	}
}

func (h *Handler) handlePasswordCallback(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
	host, port, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		h.logger.Error("Error splitting host and port", "error", err)
	}

	// Get the ASN and Country
	var country, asn string
	// Parse net addr for geoip2 to use
	hostAddr, err := netip.ParseAddr(host)
	if err != nil {
		h.logger.Error("Unable to parse net addr from host", "host", host, "error", err)
		country = "Unknown"
		asn = "Unknown"
	} else {
		record, err := h.countryDB.Country(hostAddr)
		if err != nil {
			h.logger.Error("Unable to parse country from IP", "host", host, "error", err)
		}

		if record.HasData() {
			country = record.Country.Names.English
		} else {
			country = "Unknown"
		}

		asnRecord, err := h.asnDB.ASN(hostAddr)
		if err != nil {
			h.logger.Error("Unable to parse ASN from IP", "host", host, "error", err)
		}

		if asnRecord.HasData() {
			asn = asnRecord.AutonomousSystemOrganization
		} else {
			asn = "Unknown"
		}
	}

	e := event.Event{
		NodeID:        h.nodeID,
		Timestamp:     time.Now(),
		SourceIP:      host,
		SourcePort:    port,
		Username:      conn.User(),
		Password:      string(password),
		ClientVersion: string(conn.ClientVersion()),
		SessionID:     fmt.Sprintf("%x", conn.SessionID()),
		Country:       country,
		ASN:           asn,
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
