package db

import (
	"database/sql"

	_ "modernc.org/sqlite"
)

func MakeDB() (*sql.DB, error) {
	// Using SQLite as number of users won't be many. Just for added security.
	db, err := sql.Open("sqlite", "./data/freepn.db")
	if err != nil {
		return nil, err
	}

	// Table of authorized VPN users
	run := `CREATE TABLE IF NOT EXISTS authorized_users (
		id TEXT NOT NULL PRIMARY KEY,
		password TEXT NOT NULL
		is_first_login BOOLEAN DEFAULT TRUE
	)`

	_, err = db.Exec(run)

	if err != nil {
		return nil, err
	}

	// Pointer to the db
	return db, nil
}

func AddAuthorizedUser(user string, hashedPassword string, db *sql.DB) error {

	// Default new users to "TRUE" for first time boolean
	run := `INSERT INTO authorized_users 
			VALUES (?, ?, ?)`
	_, err := db.Exec(run, user, hashedPassword, 1)

	if err != nil {
		return err
	}

	return nil
}

func UpdateUserPassword(user string, newPassword string, db *sql.DB) error {

	run := `UPDATE authorized_users
			SET password = ?
			WHERE id = ?`

	_, err := db.Exec(run, newPassword, user)

	if err != nil {
		return err
	}

	return nil
}
