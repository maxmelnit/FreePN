//go:build linux

package vpn

import (
	"client/auth"
	"client/tun"
	"encoding/json"
	"errors"
	"log"
	"net"
	"os"
)

type Config struct {
	Host string `json:"server_address"`
	Port string `json:"server_port"`
}

const udpBufferSize = 4 * 1024 * 1024

func LaunchClient() error {

	var cfg Config
	jsonData, err := os.ReadFile("./config.json")
	if err != nil {
		return err
	}
	err = json.Unmarshal(jsonData, &cfg)
	if err != nil {
		return err
	}

	host := cfg.Host
	port := cfg.Port

	log.Println("Found server in configuration file. Connecting to: " + host + ":" + port)

	// Open TUN
	fd, err := tun.OpenTUN("client-tun")
	if err != nil {

		return err
	}
	defer fd.Close()

	// Configure TUN with custom settings
	err = tun.ConfigureTUN(
		"client-tun",
		"10.8.0.2/24",
		tun.MTU,
	)
	if err != nil {
		return err
	}

	// Get or create a new private client key
	clientPrivateKey, err := auth.LoadOrCreateClientKey("./keys/client.key")
	if err != nil {
		return err
	}

	// Dial the server
	serverAddr, err := net.ResolveUDPAddr("udp", host+":"+port)
	if err != nil {
		return err
	}
	serverConn, err := net.DialUDP("udp", nil, serverAddr)
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

	// Send the raw client public key to the server
	clientPublicKey := clientPrivateKey.PublicKey().Bytes()
	_, err = serverConn.Write(clientPublicKey)
	if err != nil {
		return err
	}

	// Get the server's public key
	isAllowed, serverPublicKey, err := auth.AuthServerKey(serverConn)
	if err != nil {
		return err
	}
	if !isAllowed {
		return errors.New("server public key not allowed")
	}

	// Calculate the shared secret with DH
	sharedSecret, err := auth.DHKeyExchange(clientPrivateKey, serverPublicKey)
	if err != nil {
		return err
	}

	encryptCipher, err := auth.NewPacketCipher(sharedSecret)
	if err != nil {
		return err
	}

	decryptCipher, err := auth.NewPacketCipher(sharedSecret)
	if err != nil {
		return err
	}

	// Goroutine helps prevent blocking during reading
	go func() {

		// Buffer to hold incoming packet data (includes some buffer for overhead)
		buffer := make([]byte, 2048)

		for {
			n, err := serverConn.Read(buffer)
			if err != nil {
				log.Println("Error reading from client: " + err.Error())
				return
			}

			packet, err := auth.Decrypt(decryptCipher, buffer[:n])
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

	// Writing packets to the VPN server
	writeBuffer := make([]byte, 2048)

	// Read the application data from TUN and store in the buffer
	for {
		n, err := fd.Read(writeBuffer)
		if err != nil {
			log.Println("Error reading from TUN: " + err.Error())
			return err
		}

		// Encrypt the packet and send off to the server
		encryptedPacket := auth.Encrypt(encryptCipher, writeBuffer[:n])

		_, err = serverConn.Write(encryptedPacket)
		if err != nil {
			log.Println("Packet write error: " + err.Error())
			return err
		}
	}
}
