package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
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

	if n != 32 {
		log.Println("Client key is not 32 bytes long")
		return false, nil, nil, errors.New("invalid client key, not 32 bytes long")
	}

	// We receive bytes from the client, so convert it to base64
	receivedKeyBase64 := base64.StdEncoding.EncodeToString(buffer[:n])

	// Check if client key is in the allowlist
	if !slices.Contains(config.ClientID, receivedKeyBase64) {
		return false, nil, nil, errors.New("client public key not in allowlist")
	}

	return true, buffer[:n], addr, nil
}

// LoadOrCreateServerKey Loads the server key from the file, or generates a new one
func LoadOrCreateServerKey(filename string) (*ecdh.PrivateKey, error) {
	curve := ecdh.X25519()

	savedKey, err := os.ReadFile(filename)
	if err == nil {
		if len(savedKey) != 32 {
			return nil, fmt.Errorf(
				"invalid server private key length: %d",
				len(savedKey),
			)
		}

		privateKey, err := curve.NewPrivateKey(savedKey)
		if err != nil {
			return nil, fmt.Errorf("load server private key: %w", err)
		}

		return privateKey, nil
	}

	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read server private key: %w", err)
	}

	privateKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate server private key: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(filename), 0700); err != nil {
		return nil, fmt.Errorf("create server key directory: %w", err)
	}

	keyFile, err := os.OpenFile(
		filename,
		os.O_WRONLY|os.O_CREATE|os.O_EXCL,
		0600,
	)
	if err != nil {
		return nil, fmt.Errorf("create server key file: %w", err)
	}

	if _, err := keyFile.Write(privateKey.Bytes()); err != nil {
		_ = keyFile.Close()
		return nil, fmt.Errorf("save server private key: %w", err)
	}

	if err := keyFile.Close(); err != nil {
		return nil, fmt.Errorf("close server key file: %w", err)
	}

	publicKeyBase64 := base64.StdEncoding.EncodeToString(
		privateKey.PublicKey().Bytes(),
	)

	fmt.Println("New server key created.")
	fmt.Println("Add this public key to the client configuration:")
	fmt.Println(publicKeyBase64)

	return privateKey, nil
}

// DHKeyExchange Used to determine secret key between client and server
func DHKeyExchange(serverPrivateKey *ecdh.PrivateKey, clientPublicKeyBytes []byte) ([]byte, error) {
	curve := ecdh.X25519()

	if len(clientPublicKeyBytes) != 32 {
		return nil, fmt.Errorf(
			"invalid client public key length: %d",
			len(clientPublicKeyBytes),
		)
	}

	clientPublicKey, err := curve.NewPublicKey(clientPublicKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("parse client public key: %w", err)
	}

	sharedSecret, err := serverPrivateKey.ECDH(clientPublicKey)
	if err != nil {
		return nil, fmt.Errorf("derive shared secret: %w", err)
	}

	return sharedSecret, nil
}
