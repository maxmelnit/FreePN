package vpn

import (
	"server/auth"
	"server/transport"
)

// PORT to start server on
var PORT string = ":55555"

func LaunchFreePN() {

	// Start the server
	serverConn, err := transport.StartServer(PORT)

	if err != nil {
		return
	}
	defer serverConn.Close()

	// When connection is established with client, authenticate that client
	res, err := auth.AuthClientKey(serverConn)

	// Failed auth
	if err != nil || !res {
		return
	}

	// Diffie-Hellman key exchange

	// Listen for incoming packets
	packetChannel := transport.ReceiveUDP(serverConn)

}
