package main

import (
	"database/sql"
	"flag"
	"fmt"
	"io/ioutil"
	"log"

	_ "github.com/mattn/go-sqlite3"
)

func main() {
	// Command line flags
	dbPath := flag.String("db", "clients.db", "Path to SQLite database file")
	migrationsPath := flag.String("migrations", "./", "Path to migration scripts directory")
	flag.Parse()

	// Open database connection
	db, err := sql.Open("sqlite3", *dbPath)
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	// Read migration file
	migrationFile := fmt.Sprintf("%s/init.sql", *migrationsPath)
	migrationSQL, err := ioutil.ReadFile(migrationFile)
	if err != nil {
		log.Fatalf("Failed to read migration file: %v", err)
	}

	// Execute migration
	_, err = db.Exec(string(migrationSQL))
	if err != nil {
		log.Fatalf("Failed to execute migration: %v", err)
	}

	log.Printf("Database migration completed successfully")
}
