package auth

import (
	"crypto/ecdsa"
	"crypto/x509"

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

// IssueClientCert Issue a client certificate for the connecting client
func IssueClientCert(request x509.CertificateRequest, caKey *ecdsa.PrivateKey) ([]byte, []byte) {

	parsed, _ := x509.ParseCertificate(request)
}
