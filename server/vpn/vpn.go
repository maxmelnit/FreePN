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
	res, clientPublicKey, err := auth.AuthClientKey(serverConn)

	// Failed auth
	if err != nil || !res {
		return
	}

	// Diffie-Hellman key exchange
	sharedSecret := auth.DHKeyExchange(clientPublicKey)

	// Listen for incoming packets
	packetChan := transport.ReceiveUDP(serverConn)

	// Decrypt each packet received in the channel
	for packet := range packetChan {
		decryptedPacket, _ := auth.Decrypt(sharedSecret, packet)

		// Get decrypted packet IP
		decryptedPacketIP := transport.GetIPDest(decryptedPacket)

	}

}
