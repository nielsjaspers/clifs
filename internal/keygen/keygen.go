package keygen

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"
)

func GenerateKeys() error {
	if _, err := os.Stat("server-env"); os.IsNotExist(err) {
		if err := os.Mkdir("server-env", os.ModePerm); err != nil {
			return fmt.Errorf("Error creating directory: %v\n", err)
		}
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("Error while generating key: %v\n", err)
	}
	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour)

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("Error generating serial number: %v\n", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"clifs - command-line interface file sharing"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return fmt.Errorf("Error creating DER bytes: %v\n", err)
	}

	certOut, err := os.Create("server-env/cert.pem")
	if err != nil {
		return fmt.Errorf("Error creating file: %v\n", err)
	}
	defer certOut.Close()
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	keyOut, err := os.Create("server-env/key.pem")
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

func pemBlockForKey(priv *ecdsa.PrivateKey) (*pem.Block, error) {
	b, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	return &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}, nil
}
