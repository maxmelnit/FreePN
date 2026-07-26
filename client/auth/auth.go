package auth

import (
	"bytes"
	"client/transport"
	"crypto/aes"
	"crypto/cipher"
	"log"
	"net"
	"os"
)

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

// AuthServerKey Check if the server we're establishing a connection with is the real one
func AuthServerKey(conn *net.UDPConn) bool {

	expected := os.Getenv("SERVER_PUB")

	// Pop the first packet from the channel
	channel := transport.ReceiveUDP(conn)
	actual := <-channel

	if !bytes.Equal([]byte(expected), actual) {
		log.Println("Server public key mismatch")
		return false
	}

	return true
}
