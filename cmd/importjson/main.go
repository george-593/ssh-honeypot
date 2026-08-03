package main

import (
	"encoding/json"
	"log"
	"log/slog"
	"os"

	"github.com/george-593/ssh-honeypot/internal/event"
	"github.com/george-593/ssh-honeypot/internal/storage"
)

const sqlPath string = "data/events.sql"

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	if len(os.Args) < 2 {
		log.Fatalf("usage: %s <path-to-ndjson-log>", os.Args[0])
	}
	jsonPath := os.Args[1]

	// Read NDJSON logs
	logger.Info("Reading JSON logs from", "path", jsonPath)
	reader, err := os.Open(jsonPath)
	if err != nil {
		log.Fatal(err)
	}
	defer reader.Close()

	decoder := json.NewDecoder(reader)

	// Create SQL storage
	logger.Info("Creating SQL storage", "path", sqlPath)
	store, err := storage.NewSQLiteStorage(sqlPath)
	if err != nil {
		log.Fatal(err)
	}
	defer store.Close()

	// Import JSON logs into SQL
	logger.Info("Importing JSON logs into SQL", "path", sqlPath)
	var count int
	for decoder.More() {
		var e event.Event
		if err := decoder.Decode(&e); err != nil {
			log.Fatal(err)
		}

		if err := store.Store(e); err != nil {
			log.Fatal(err)
		}

		count++
		if count%50000 == 0 {
			logger.Info("Import progress", "rows", count)
		}
	}

	logger.Info("Import completed successfully.", "rows", count)
}
