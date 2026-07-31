//go:build Linux
package vpn

import (
	"server/auth"
	"server/transport"
	"server/tun"
)

// PORT to start server on
var PORT string = ":55555"

func LaunchFreePN() {

	// Open TUN server side
	fd, err := tun.OpenTUN()

	if err != nil {
		log.Println("Error opening tunnel: " + err.Error())
	}

	// Start the server
	serverConn, err := transport.StartServer(PORT)

	if err != nil {
		return
	}
	defer serverConn.Close()

	// When connection is established with client, authenticate that client
	res, clientPublicKey, err := auth.AuthClientKey(serverConn)

	// Failed auth
	if err != nil || !res {
		return
	}

	// Diffie-Hellman key exchange
	sharedSecret := auth.DHKeyExchange(clientPublicKey)

	// Listen for incoming packets
	packetChan := transport.ReceiveUDP(serverConn)

	
	go func() {
		transport.
	}()

	}

}
