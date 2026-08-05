//go:build linux

package vpn

import (
	"errors"
	"log"
	"server/auth"
	"server/transport"
	"server/tun"
	"sync"
)

// PORT to start server on
var PORT string = ":55555"

const udpBufferSize = 4 * 1024 * 1024

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

	err = serverConn.SetReadBuffer(udpBufferSize)
	if err != nil {
		return err
	}

	err = serverConn.SetWriteBuffer(udpBufferSize)
	if err != nil {
		return err
	}

	// Get the server's private key
	serverPrivateKey, err := auth.LoadOrCreateServerKey("./keys/server.key")
	if err != nil {
		return err
	}

	// When connection is established with client, authenticate that client
	isAllowed, clientPublicKey, clientAddr, err := auth.AuthClientKey(serverConn)

	// Failed auth
	if err != nil {
		return err
	}
	if !isAllowed {
		return errors.New("client public key not in allowlist")
	}

	var clientAddrMu sync.RWMutex

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

			packet, err := auth.Decrypt(sharedSecret, buffer[:n])
			if err != nil {
				log.Println("Packet decryption error: " + err.Error())
				continue
			}

			// Only trust the new address after successful decryption.
			clientAddrMu.Lock()
			if addr.String() != clientAddr.String() {
				log.Printf(
					"Authenticated client address changed: %s -> %s",
					clientAddr,
					addr,
				)
			}
			clientAddr = addr
			clientAddrMu.Unlock()

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

		clientAddrMu.RLock()
		destination := clientAddr
		clientAddrMu.RUnlock()

		_, err = serverConn.WriteToUDP(encrypted, destination)
		if err != nil {
			log.Println("Error writing to client: " + err.Error())
		}

	}

}
