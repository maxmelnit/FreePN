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

func LaunchFreePN() error {

	// Open TUN server side
	fd, err := tun.OpenTUN("server-tun")

	if err != nil {
		log.Println("Error opening tunnel: " + err.Error())
		return err
	}
	defer fd.Close()

	// Start the server
	serverConn, err := transport.StartServer(PORT)

	if err != nil {
		return err
	}
	defer serverConn.Close()

	// Get the server's private key
	serverPrivateKey, err := auth.LoadOrCreateServerKey("./keys/server.key")
	if err != nil {
		return err
	}

	// When connection is established with client, authenticate that client
	isAllowed, clientPublicKey, clientAddr, err := auth.AuthClientKey(serverConn)

	// Failed auth
	if err != nil || !isAllowed {
		return err
	}

	// Diffie-Hellman key exchange
	sharedSecret, err := auth.DHKeyExchange(serverPrivateKey, clientPublicKey)
	if err != nil {
		return err
	}

	// Send the raw server public key to the client.
	serverPublicKey := serverPrivateKey.PublicKey().Bytes()
	_, err = serverConn.WriteToUDP(serverPublicKey, clientAddr)
	if err != nil {
		return err
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

			_, err = fd.Write(packet)
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
			return err
		}

		encrypted, err := auth.Encrypt(sharedSecret, writeBuffer[:n])
		if err != nil {
			log.Println("Error encrypting packet: " + err.Error())
			continue
		}

		_, err = serverConn.WriteToUDP(encrypted, clientAddr)
		if err != nil {
			log.Println("Error writing to client: " + err.Error())
		}

	}

}
