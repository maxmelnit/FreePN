package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
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

func Encrypt(key []byte, data []byte) ([]byte, error) {

	// Make a unique cipher block
	block, err := aes.NewCipher(key)

	if err != nil {
		log.Println("Could not initialize cipher block: " + err.Error())
		return nil, err
	}

	// GCM: Make into stream cipher + add tamper prevention (tag and nonce)
	gcm, err := cipher.NewGCMWithRandomNonce(block)

	if err != nil {
		log.Println("Could not wrap AES in GCM: " + err.Error())
		return nil, err
	}

	// Encrypt and return the data
	encrypted := gcm.Seal(nil, nil, data, nil)

	return encrypted, nil

}

func Decrypt(key []byte, data []byte) ([]byte, error) {

	block, err := aes.NewCipher(key)

	if err != nil {
		log.Println("Could not initialize cipher block: " + err.Error())
		return nil, err
	}

	gcm, err := cipher.NewGCMWithRandomNonce(block)

	if err != nil {
		log.Println("Could not wrap AES in GCM: " + err.Error())
		return nil, err
	}

	res, err := gcm.Open(nil, nil, data, nil)

	if err != nil {
		log.Println("Error decrypting data: " + err.Error())
		return nil, err
	}

	return res, nil
}

// AuthClientKey Lets the server authenticate that the connected client is authorized
func AuthClientKey(conn *net.UDPConn) (bool, []byte, error) {

	// Multiple clients can be connected
	type ClientConfig struct {
		ClientID []string `json:"allowed_clients"`
	}

	// Can be optimized by loading one time, but this is ok for my use case
	data, err := os.ReadFile("./config.json")

	if err != nil {
		log.Println("Error reading config file: " + err.Error())
		return false, nil, err
	}

	var config ClientConfig
	err = json.Unmarshal(data, &config)

	if err != nil {
		log.Println("Error parsing config file: " + err.Error())
		return false, nil, err
	}

	// Get first packet received from channel (the clients public key), as part of initial handshake
	channel := transport.ReceiveUDP(conn)
	packet := <-channel

	// Check if the client's public key matches an authorized key in the config
	if slices.Contains(config.ClientID, string(packet)) {
		log.Println("Client authenticated")
		return true, packet, nil
	}

	return false, nil, nil
}

// DHKeyExchange Used to determine secret key between client and server
func DHKeyExchange(clientPublicKey []byte) []byte {

	curve := ecdh.X25519()
	serverPrivate, _ := curve.GenerateKey(rand.Reader)

	clientPubBytes, _ := curve.NewPublicKey(clientPublicKey)

	// Shared secret derived from server private key + client public key
	sharedSecret, _ := serverPrivate.ECDH(clientPubBytes)

	return sharedSecret

}
