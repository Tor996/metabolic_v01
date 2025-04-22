package sqlite

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/sqlite3"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	_ "github.com/mattn/go-sqlite3"
)

const (
	defaultDBName = "metabolic.db"
)

// User struct to match the database schema
type User struct {
	ID        int64
	Email     string
	Password  string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// DB represents a database connection
type DB struct {
	*sql.DB
	dbPath string
}

// New creates a new SQLite database connection
func New(dbPath string) (*DB, error) {
	// Use default path if none provided
	if dbPath == "" {
		// Ensure db directory exists
		if err := os.MkdirAll("db/sqlite", 0755); err != nil {
			return nil, fmt.Errorf("failed to create db directory: %w", err)
		}
		dbPath = filepath.Join("db/sqlite", defaultDBName)
	} else {
		// Ensure directory exists for custom path
		dir := filepath.Dir(dbPath)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create db directory: %w", err)
		}
	}

	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Test the connection
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	return &DB{DB: db, dbPath: dbPath}, nil
}

// RunMigrations runs the database migrations
func (db *DB) RunMigrations() error {
	driver, err := sqlite3.WithInstance(db.DB, &sqlite3.Config{})
	if err != nil {
		return fmt.Errorf("could not create migration driver: %w", err)
	}

	m, err := migrate.NewWithDatabaseInstance(
		"file://db/migrations",
		"sqlite3", driver)
	if err != nil {
		return fmt.Errorf("could not create migration instance: %w", err)
	}

	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		return fmt.Errorf("failed to run migrations: %w", err)
	}

	log.Println("Database migrations applied successfully")
	return nil
}

// GetUserByEmail retrieves a user by email
func (db *DB) GetUserByEmail(email string) (*User, error) {
	query := `SELECT id, email, password, created_at, updated_at FROM users WHERE email = ?`
	
	var user User
	var createdAt, updatedAt string
	err := db.QueryRow(query, email).Scan(
		&user.ID, 
		&user.Email, 
		&user.Password,
		&createdAt,
		&updatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil // No user found
		}
		return nil, fmt.Errorf("error querying user: %w", err)
	}
	
	// Parse timestamps with proper error handling
	user.CreatedAt, err = time.Parse(time.RFC3339, createdAt)
	if err != nil {
		return nil, fmt.Errorf("error parsing created_at timestamp: %w", err)
	}
	
	user.UpdatedAt, err = time.Parse(time.RFC3339, updatedAt)
	if err != nil {
		return nil, fmt.Errorf("error parsing updated_at timestamp: %w", err)
	}
	
	return &user, nil
}

// CreateUser creates a new user in the database
func (db *DB) CreateUser(email, hashedPassword string) error {
	query := `INSERT INTO users (email, password, created_at, updated_at) 
              VALUES (?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`
	
	_, err := db.Exec(query, email, hashedPassword)
	if err != nil {
		return fmt.Errorf("error creating user: %w", err)
	}
	
	return nil
}

// UpdateUser updates an existing user's information
func (db *DB) UpdateUser(userID int64, updates map[string]interface{}) error {
	// Build query and parameters separately for safety
	var setClauses []string
	var params []interface{}
	
	// Add each field to be updated
	for field, value := range updates {
		// Only allow specific fields to be updated for security
		switch field {
		case "email", "password":
			setClauses = append(setClauses, field+" = ?")
			params = append(params, value)
		default:
			// Skip invalid fields
			continue
		}
	}
	
	// Always update the updated_at timestamp
	setClauses = append(setClauses, "updated_at = CURRENT_TIMESTAMP")
	
	// If no valid fields were provided, just exit
	if len(setClauses) <= 1 {
		// Only the timestamp is being updated, which is pointless alone
		return nil
	}
	
	// Build the final query
	query := "UPDATE users SET " + strings.Join(setClauses, ", ") + " WHERE id = ?"
	params = append(params, userID)
	
	// Execute the query
	_, err := db.Exec(query, params...)
	if err != nil {
		return fmt.Errorf("error updating user: %w", err)
	}
	
	return nil
} 