package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"log"
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

// Generate the private + public keys
func GenKeyPair() (*ecdh.PrivateKey, *ecdh.PublicKey, error) {

	// Using the X25519 elliptic curve
	curve := ecdh.X25519()
	privateKey, err := curve.GenerateKey(rand.Reader)

	if err != nil {
		log.Println("Error generating private key: " + err.Error())
		return nil, nil, err
	}

	// Pub key derived from priv key
	publicKey := privateKey.PublicKey()

	return privateKey, publicKey, nil
}

// Generates the shared secret between the client and server
func GenSharedSecret(clientPrivateKey *ecdh.PrivateKey, serverPublicKey *ecdh.PublicKey) ([]byte, error) {

	shared, err := clientPrivateKey.ECDH(serverPublicKey)

	if err != nil {
		log.Println("Diffie-Hellman key exchange failed: " + err.Error())
		return nil, err
	}

	// Just for some extra security, we can make the shared key a SHA-256 hash
	sha := sha256.Sum256(shared)
	return sha[:], nil
}
