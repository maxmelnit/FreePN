//go:build linux

package main

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"server/auth"
	"server/db"
	"server/vpn"
	"strings"
)

func main() {

	if len(os.Args) != 2 {
		fmt.Println("Usage: freepn [init|run]")
		return
	}

	if os.Args[1] == "init" {
		serverPrivateKey, err :=
			auth.LoadOrCreateServerKey("./keys/server.key")
		if err != nil {
			log.Fatal("Failed to initialize server key: " + err.Error())
		}

		publicKey := base64.StdEncoding.EncodeToString(
			serverPrivateKey.PublicKey().Bytes(),
		)

		fmt.Println("Server public key:", publicKey)
		fmt.Println("Add this to client/config.json under server_public_key.")
		return
	}

	if os.Args[1] != "run" {
		fmt.Println("Unknown command:", os.Args[1])
		return
	}

	scanner := bufio.NewScanner(os.Stdin)
	var id string
	var password string

	file, err := os.OpenFile("./logs/server.log", os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0644)

	if err != nil {
		log.Fatal("Error opening server log file: " + err.Error())
	}

	defer file.Close()

	// Set the global logging output to the server.log file instead of stderr
	log.SetOutput(file)

	log.Println("Booting FreePN server...")

	// Try to make a user database if it doesn't exist
	database, err := db.MakeDB()
	if err != nil {
		log.Fatal("Error creating user database: " + err.Error())
	}
	defer database.Close()

	dbUsers, err := db.GetUsers(database)
	if err != nil {
		log.Fatal("Could not fetch database users: " + err.Error())
	}
	defer dbUsers.Close()

	// If the database is empty, prompt the user to create a new user
	if !dbUsers.Next() {
		fmt.Println("There are currently no authorized users configured. [Y] to configure, [N] to exit.")
		scanner.Scan()
		res := scanner.Text()

		if strings.ToLower(res) == "y" {

			fmt.Println("Set a user ID:")
			scanner.Scan()
			id = scanner.Text()
			fmt.Println("Set a password:")
			scanner.Scan()
			password, err = auth.HashedPassword(scanner.Text())

			if err != nil {
				log.Fatal("Error configuring user password: " + err.Error())
			}

			// Add the user to the SQLite DB
			err = db.AddAuthorizedUser(id, password, database)

			if err != nil {
				log.Fatal("Could not add user " + id + " to list of authorized users: " + err.Error())
			}

			fmt.Println("User created with id: '" + id + "'")
		} else {
			log.Fatal("User cancelled user creation. Exiting.")
		}
	}

	fmt.Println("Options:\n1. Add a new user\n2. Remove an existing user\n3. View all users\n4. Start FreePN")
	scanner.Scan()
	res := scanner.Text()

	if res == "4" {
		err := vpn.LaunchFreePN()
		if err != nil {
			log.Fatal("Error launching FreePN server: " + err.Error())
		}
	}

}
