package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"errors"
	"log"
	"net"
	"os"
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
func AuthClientKey(conn *net.UDPConn) (bool, []byte, *net.UDPAddr, error) {

	// Multiple clients can be connected
	type ClientConfig struct {
		ClientID []string `json:"allowed_clients"`
	}

	// Can be optimized by loading one time, but this is ok for my use case
	data, err := os.ReadFile("./config.json")

	if err != nil {
		log.Println("Error reading config file: " + err.Error())
		return false, nil, nil, err
	}

	var config ClientConfig
	err = json.Unmarshal(data, &config)

	if err != nil {
		log.Println("Error parsing config file: " + err.Error())
		return false, nil, nil, err
	}

	// Client key is X25519, which is 32 bytes long
	buffer := make([]byte, 32)

	// Read UDP data and store in buffer
	n, addr, err := conn.ReadFromUDP(buffer)
	if err != nil {
		return false, nil, nil, err
	}

	// Check if client key is in the allowlist
	if !slices.Contains(config.ClientID, string(buffer[:n])) {
		return false, nil, nil, errors.New("client public key not in allowlist")
	}

	return true, buffer[:n], addr, nil
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
