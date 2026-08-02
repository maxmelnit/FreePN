//go:build linux

package main

import (
	"client/vpn"
	"log"
)

func main() {
	log.Println("Booting FreePN...")
	err := vpn.LaunchClient()
	if err != nil {
		log.Fatal("FreePN client stopped: " + err.Error())
	}

	// Authenticate with JWT, then Diffie-Hellman

}
