package main

import (
	"database/sql"
	"log"
	"log/slog"
	"net/netip"
	"os"

	"github.com/oschwald/geoip2-golang/v2"
	_ "modernc.org/sqlite"
)

const sqlPath string = "data/events.sql"

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	// Open DB
	db, err := sql.Open("sqlite", sqlPath+"?_pragma=busy_timeout(5000)")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// Open GeoIP DBs
	countryDB, err := geoip2.Open("data/GeoLite2-Country.mmdb")
	if err != nil {
		log.Fatal(err)
	}
	defer countryDB.Close()

	asnDB, err := geoip2.Open("data/GeoLite2-ASN.mmdb")
	if err != nil {
		log.Fatal(err)
	}
	defer asnDB.Close()

	// Find rows that still need enrichment
	rows, err := db.Query("SELECT id, source_ip FROM events WHERE country = 'Unknown' OR asn = 'Unknown'")
	if err != nil {
		log.Fatal(err)
	}

	type target struct {
		id       int64
		sourceIP string
	}
	var targets []target
	for rows.Next() {
		var t target
		if err := rows.Scan(&t.id, &t.sourceIP); err != nil {
			log.Fatal(err)
		}
		targets = append(targets, t)
	}
	if err := rows.Err(); err != nil {
		log.Fatal(err)
	}
	rows.Close()

	logger.Info("Rows to backfill", "count", len(targets))

	// Update in a single transaction
	tx, err := db.Begin()
	if err != nil {
		log.Fatal(err)
	}

	stmt, err := tx.Prepare("UPDATE events SET country = ?, asn = ? WHERE id = ?")
	if err != nil {
		log.Fatal(err)
	}
	defer stmt.Close()

	var updated int
	for _, t := range targets {
		country := "Unknown"
		asn := "Unknown"

		hostAddr, err := netip.ParseAddr(t.sourceIP)
		if err != nil {
			logger.Error("Unable to parse net addr from source_ip", "id", t.id, "source_ip", t.sourceIP, "error", err)
		} else {
			countryRecord, err := countryDB.Country(hostAddr)
			if err != nil {
				logger.Error("Unable to parse country from IP", "id", t.id, "source_ip", t.sourceIP, "error", err)
			}
			if countryRecord.HasData() {
				country = countryRecord.Country.Names.English
			}

			asnRecord, err := asnDB.ASN(hostAddr)
			if err != nil {
				logger.Error("Unable to parse ASN from IP", "id", t.id, "source_ip", t.sourceIP, "error", err)
			}
			if asnRecord.HasData() {
				asn = asnRecord.AutonomousSystemOrganization
			}
		}

		if _, err := stmt.Exec(country, asn, t.id); err != nil {
			log.Fatal(err)
		}

		updated++
		if updated%50000 == 0 {
			logger.Info("Backfill progress", "rows", updated)
		}
	}

	if err := tx.Commit(); err != nil {
		log.Fatal(err)
	}

	logger.Info("Backfill completed successfully.", "rows", updated)
}
