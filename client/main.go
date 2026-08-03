//go:build linux

package main

import (
	"client/auth"
	"client/vpn"
	"encoding/base64"
	"fmt"
	"log"
	"os"
)

func main() {

	if len(os.Args) != 2 {
		fmt.Println("Usage: freepn [init|run]")
		return
	}

	// Command line args, allows either initializing the client key or starting the VPN
	switch os.Args[1] {
	case "init":
		clientPrivateKey, err := auth.LoadOrCreateClientKey("./keys/client.key")
		if err != nil {
			log.Fatal("Failed to generate client private key")
		}

		clientPublicKeyBase64 := base64.StdEncoding.EncodeToString(clientPrivateKey.PublicKey().Bytes())

		fmt.Println("Client public key: " + clientPublicKeyBase64)
		fmt.Println("Add this key to server config.json under allowed_clients")

	case "run":
		log.Println("Booting FreePN...")
		fmt.Println("Booting FreePN...")
		err := vpn.LaunchClient()
		if err != nil {
			fmt.Println("FreePN client stopped: " + err.Error())
			log.Fatal("FreePN client stopped: " + err.Error())
		}

		log.Println("FreePN is up!")
		fmt.Println("FreePN is up!")

	default:
		fmt.Println("Unknown command: " + os.Args[1])
	}

}
