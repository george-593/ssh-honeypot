package storage

import (
	"database/sql"
	"time"

	"github.com/george-593/ssh-honeypot/internal/event"
	_ "modernc.org/sqlite"
)

const createEventsTable = `
CREATE TABLE IF NOT EXISTS events (
	id INTEGER PRIMARY KEY,
	node_id TEXT NOT NULL,
	timestamp DATETIME NOT NULL,
	source_ip TEXT NOT NULL,
	source_port TEXT NOT NULL,
	username TEXT NOT NULL,
	password TEXT NOT NULL,
	client_version TEXT NOT NULL,
	session_id TEXT NOT NULL,
	country TEXT NOT NULL,
	asn TEXT NOT NULL,
	synced_at DATETIME
)
`

type SQLiteStorage struct {
	db        *sql.DB
	statement *sql.Stmt
}

func NewSQLiteStorage(path string) (*SQLiteStorage, error) {
	// Open DB
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}

	// Create events table
	_, err = db.Exec(createEventsTable)
	if err != nil {
		return nil, err
	}

	// Enable WAL mode
	_, err = db.Exec("PRAGMA journal_mode=WAL")
	if err != nil {
		return nil, err
	}

	// Prepare insert statement
	stmt, err := db.Prepare("INSERT INTO events (node_id, timestamp, source_ip, source_port, username, password, client_version, session_id, country, asn) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
	if err != nil {
		return nil, err
	}

	return &SQLiteStorage{db: db, statement: stmt}, nil
}

func (s *SQLiteStorage) Store(e event.Event) error {
	_, err := s.statement.Exec(e.NodeID, e.Timestamp.UTC().Format(time.RFC3339Nano), e.SourceIP, e.SourcePort, e.Username, e.Password, e.ClientVersion, e.SessionID, e.Country, e.ASN)
	return err
}

func (s *SQLiteStorage) Close() error {
	// Close Statement
	err := s.statement.Close()
	if err != nil {
		return err
	}

	// Close DB
	err = s.db.Close()
	return err
}
