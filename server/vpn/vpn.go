//go:build linux

package vpn

import (
	"log"
	"server/auth"
	"server/transport"
	"server/tun"
)

// PORT to start server on
var PORT string = ":55555"

func LaunchFreePN() {

	// Open TUN server side
	fd, err := tun.OpenTUN("server-tun")

	if err != nil {
		log.Println("Error opening tunnel: " + err.Error())
		return
	}
	defer fd.Close()

	// Start the server
	serverConn, err := transport.StartServer(PORT)

	if err != nil {
		return
	}
	defer serverConn.Close()

	// When connection is established with client, authenticate that client
	isAllowed, clientPublicKey, clientAddr, err := auth.AuthClientKey(serverConn)

	// Failed auth
	if err != nil || !isAllowed {
		return
	}

	// Diffie-Hellman key exchange
	sharedSecret, serverPublicKey := auth.DHKeyExchange(clientPublicKey)

	// Send the client the server public key for authentication
	_, err = serverConn.WriteToUDP(serverPublicKey, clientAddr)
	if err != nil {
		return
	}

	// Goroutine helps prevent blocking during reading
	go func() {

		// Buffer to hold incoming packet data (includes some buffer for overhead)
		buffer := make([]byte, 2048)

		for {
			n, addr, err := serverConn.ReadFromUDP(buffer)
			if err != nil {
				log.Println("Error reading from client: " + err.Error())
				return
			}

			// If the packets aren't coming from the authenticated client address
			if addr.String() != clientAddr.String() {
				log.Println("Client address mismatch")
				continue
			}

			packet, err := auth.Decrypt(sharedSecret, buffer[:n])
			if err != nil {
				log.Println("Packet decryption error: " + err.Error())
				continue
			}

			_, err := fd.Write(packet)
			if err != nil {
				log.Println("Error writing packet to TUN: " + err.Error())
				return
			}

		}
	}()

	// Now, server TUN relays data back to the client
	writeBuffer := make([]byte, 2048)
	for {
		n, err := fd.Read(writeBuffer)
		if err != nil {
			log.Println("Error reading from TUN: " + err.Error())
			return
		}

		encrypted, err := auth.Encrypt(sharedSecret, writeBuffer[:n])
		if err != nil {
			log.Println("Error encrypting packet: " + err.Error())
			continue
		}

		_, err := serverConn.WriteToUDP(encrypted, clientAddr)
		if err != nil {
			log.Println("Error writing to client: " + err.Error())
		}

	}

}
