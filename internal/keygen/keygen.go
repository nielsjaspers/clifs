package keygen

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"time"

	"github.com/nielsjaspers/clifs/internal/config"
)

func GenerateKeys() error {
	if _, err := os.Stat(config.GetConfigDir()); os.IsNotExist(err) {
		if err := os.Mkdir(config.GetConfigDir(), os.ModePerm); err != nil {
			return fmt.Errorf("Error creating directory: %v\n", err)
		}
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("Error while generating key: %v\n", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("Error generating serial number: %v\n", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"clifs - command-line interface file sharing"},
			CommonName:   "localhost",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return fmt.Errorf("Error creating DER bytes: %v\n", err)
	}

	certOut, err := os.Create(fmt.Sprintf("%v/cert.pem", config.GetConfigDir()))
	if err != nil {
		return fmt.Errorf("Error creating file: %v\n", err)
	}
	defer certOut.Close()
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	keyOut, err := os.Create(fmt.Sprintf("%v/key.pem", config.GetConfigDir()))
	if err != nil {
		return fmt.Errorf("Error creating file: %v\n", err)
	}
	defer keyOut.Close()

	keyPemBlock, err := pemBlockForKey(priv)
	if err != nil {
		return fmt.Errorf("Error converting EC private key to SEC: %v\n", err)
	}
	pem.Encode(keyOut, keyPemBlock)

	return nil
}

func GetFingerprint(certPath string) string {
	certData, err := os.ReadFile(certPath)
	if err != nil {
		return fmt.Sprintf("Unable to read certificate file: %v\n", err)
	}
	block, _ := pem.Decode(certData)
	if block == nil {
		return "Invalid certificate"
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "Invalid certificate"
	}

	return GetFingerprintFromCert(cert)
}

func GetFingerprintFromCert(cert *x509.Certificate) string {
	fingerprint := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(fingerprint[:])
}

// CertificatesExist checks if certificate and key files exist
func CertificatesExist(certPath, keyPath string) bool {
	_, certErr := os.Stat(certPath)
	_, keyErr := os.Stat(keyPath)
	return certErr == nil && keyErr == nil
}

func pemBlockForKey(priv *ecdsa.PrivateKey) (*pem.Block, error) {
	b, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	return &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}, nil
}
