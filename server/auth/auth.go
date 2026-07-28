package auth

import (
	"encoding/json"
	"log"
	"net"
	"os"
	"server/transport"
	"slices"

	"golang.org/x/crypto/bcrypt"
)

func HashedPassword(password string) (string, error) {

	// Compute bcrypt hash with cost of 12 (2^12) hashing iterations
	res, err := bcrypt.GenerateFromPassword([]byte(password), 12)

	if err != nil {
		return "", err
	}

	return string(res), nil
}

// AuthClientKey Lets the server authenticate that the connected client is authorized
func AuthClientKey(conn *net.UDPConn) (bool, error) {

	// Multiple clients can be connected
	type ClientConfig struct {
		ClientID []string `json:"allowed_clients"`
	}

	// Can be optimized by loading one time, but this is ok for my use case
	data, err := os.ReadFile("./config.json")

	if err != nil {
		log.Println("Error reading config file: " + err.Error())
		return false, err
	}

	var config ClientConfig
	err = json.Unmarshal(data, &config)

	if err != nil {
		log.Println("Error parsing config file: " + err.Error())
		return false, err
	}

	// Get first packet received from channel (the clients public key), as part of initial handshake
	channel := transport.ReceiveUDP(conn)
	packet := <-channel

	// Check if the client's public key matches an authorized key in the config
	if slices.Contains(config.ClientID, string(packet)) {
		return true, nil
	}

	return false, nil
}
