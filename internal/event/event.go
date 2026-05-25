package event

import "time"

type Event struct {
	NodeID        string    `json:"node_id"`
	Timestamp     time.Time `json:"timestamp"`
	SourceIP      string    `json:"source_ip"`
	SourcePort    string    `json:"source_port"`
	Username      string    `json:"username"`
	Password      string    `json:"password"`
	ClientVersion string    `json:"client_version"`
	SessionID     string    `json:"session_id"`
	Country       string    `json:"country"`
	ASN           string    `json:"asn"`
}
