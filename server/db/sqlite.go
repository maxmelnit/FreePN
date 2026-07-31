package db

import (
	"database/sql"
	"log"

	_ "modernc.org/sqlite"
)

func MakeDB() (*sql.DB, error) {

	// Using SQLite to store authorized users
	db, err := sql.Open("sqlite", "./data/freepn.db")
	if err != nil {
		return nil, err
	}

	// Table of authorized VPN users
	run := `CREATE TABLE IF NOT EXISTS authorized_users (
		id TEXT NOT NULL PRIMARY KEY,
		password TEXT NOT NULL,
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

func UpdateUserPassword(user string, newHashedPassword string, db *sql.DB) error {

	run := `UPDATE authorized_users
			SET password = ?
			WHERE id = ?`

	_, err := db.Exec(run, newHashedPassword, user)

	if err != nil {
		log.Println("Error occured updating user password for '" + user + "': " + err.Error())
		return err
	}

	return nil
}

func RemoveUser(user string, db *sql.DB) error {

	run := `DELETE FROM authorized_users
			WHERE id = ?`

	_, err := db.Exec(run)

	if err != nil {
		log.Println("Error occurred deleting user '" + user + "' from database: " + err.Error())
		return err
	}

	return nil
}

func GetUsers(db *sql.DB) (*sql.Rows, error) {

	run := `SELECT * FROM authorized_users`

	res, err := db.Query(run)

	if err != nil {
		return nil, err
	}

	return res, nil
}

func ExistsUser(user string, db *sql.DB) (bool, error) {

	run := `SELECT EXISTS(SELECT 1 FROM authorized_users
			WHERE id = ?
			)`

	_, err := db.Query(run, user)

	if err != nil {
		return false, err
	}

	return true, nil
}

func GetPasswordHash(
	user string,
	db *sql.DB,
) (string, error) {
	run := `SELECT password
            FROM authorized_users
            WHERE id = ?`

	var passwordHash string

	err := db.QueryRow(run, user).Scan(&passwordHash)
	if err != nil {
		return "", err
	}

	return passwordHash, nil
}
