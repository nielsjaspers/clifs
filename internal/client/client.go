package client

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/nielsjaspers/clifs/internal/keygen"
)

func HandleClient(hostname string) {
	err := CheckServer(hostname)
	if err != nil {
		log.Fatalf("Error checking server: %v", err)
	}
	// TODO: Implement proper trust verification flow using flags
	err = TrustServer(hostname)
	if err != nil {
		log.Fatalf("Error verifying the certificates for %s: %v", hostname, err)
	}
	log.Printf("Certificates verified for %s", hostname)

}

func TrustServer(hostname string) error {
	if IsServerTrusted(hostname) {
		fingerprint := GetSavedFingerprint(hostname)
		if fingerprint == "" {
			return fmt.Errorf("server already trusted, but failed to get fingerprint")
		}
		return fmt.Errorf("server already trusted, fingerprint: %s", fingerprint)
	}
	conn, err := tls.Dial("tcp", hostname, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return fmt.Errorf("failed to dial server: %v", err)
	}
	defer conn.Close()

	cert := conn.ConnectionState().PeerCertificates[0]
	fingerprint := keygen.GetFingerprintFromCert(cert)

	fmt.Printf("Server fingerprint: %s\n", fingerprint)
	fmt.Printf("Verify this matches the server's fingerprint, then confirm.\n")

	err = saveServerCertificate("client-env", cert, hostname)
	if err != nil {
		return fmt.Errorf("failed to save server certificate: %v", err)
	}
	return nil
}

// CheckServer verifies that the server at hostname is reachable and responsive.
func CheckServer(hostname string) error {
	conn, err := tls.Dial("tcp", hostname, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return fmt.Errorf("server unreachable: %v", err)
	}
	defer conn.Close()

	return nil
}

func IsServerTrusted(hostname string) bool {
	certPath := fmt.Sprintf("client-env/%s-cert.pem", hostname)
	_, err := os.Stat(certPath)

	return err == nil
}

func GetTrustedClient(hostname string) (*http.Client, error) {
	certPath := fmt.Sprintf("client-env/%s-cert.pem", hostname)
	certData, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate: %v", err)
	}

	block, _ := pem.Decode(certData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %v", err)
	}

	caPool := x509.NewCertPool()
	caPool.AddCert(cert)

	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: caPool,
			},
		},
	}, nil
}

func GetSavedFingerprint(hostname string) string {
	certPath := fmt.Sprintf("client-env/%s-cert.pem", hostname)
	certData, err := os.ReadFile(certPath)
	if err != nil {
		return ""
	}

	block, _ := pem.Decode(certData)
	if block == nil {
		return ""
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return ""
	}

	return keygen.GetFingerprintFromCert(cert)
}

// saveServerCertificate saves the server's certificate to a file.
func saveServerCertificate(path string, cert *x509.Certificate, hostname string) error {
	if err := os.MkdirAll(path, os.ModePerm); err != nil {
		return fmt.Errorf("error creating directory: %v", err)
	}
	file, err := os.Create(fmt.Sprintf("%s/%s-cert.pem", path, hostname))
	if err != nil {
		return fmt.Errorf("error creating file: %v", err)
	}
	defer file.Close()

	return pem.Encode(file, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})

}
