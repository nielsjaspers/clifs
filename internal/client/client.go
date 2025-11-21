package client

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"

	"github.com/nielsjaspers/clifs/internal/config"
	"github.com/nielsjaspers/clifs/internal/keygen"
)

// func HandleClient(hostname string) {
// 	err := CheckServer(hostname)
// 	if err != nil {
// 		log.Fatalf("Error checking server: %v", err)
// 	}
// 	// TODO: Implement proper trust verification flow using flags
// 	err = TrustServer(hostname)
// 	if err != nil {
// 		log.Fatalf("Error verifying the certificates for %s: %v", hostname, err)
// 	}
// 	log.Printf("Certificates verified for %s", hostname)

// }
type Client struct {
	conf config.Config
}

func NewClient(conf config.Config) *Client {
	return &Client{conf: conf}
}

func (c *Client) TrustServer(hostname string) error {
	if c.IsServerTrusted(hostname) {
		fingerprint := c.GetSavedFingerprint(hostname)
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

	fmt.Printf("Verify this matches the server's fingerprint, then confirm (yes/no): ")
	var input string
	fmt.Scanln(&input)
	if input != "yes" && input != "y" {
		return fmt.Errorf("user did not confirm")
	}

	err = saveServerCertificate(c.conf.TrustedCertsDir, cert, hostname)
	if err != nil {
		return fmt.Errorf("failed to save server certificate: %v", err)
	}
	return nil
}

func (c *Client) CheckServer(hostname string) (string, error) {
	conn, err := tls.Dial("tcp", hostname, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return "", fmt.Errorf("server unreachable: %v", err)
	}
	defer conn.Close()

	cert := conn.ConnectionState().PeerCertificates[0]
	fingerprint := keygen.GetFingerprintFromCert(cert)

	return fingerprint, nil
}

func (c *Client) IsServerTrusted(hostname string) bool {
	certPath := fmt.Sprintf("%s/%s:%v-cert.pem", c.conf.TrustedCertsDir, hostname, c.conf.Port)
	certData, err := os.ReadFile(certPath)
	if err != nil {
		return false
	}

	block, _ := pem.Decode(certData)
	if block == nil {
		return false
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false
	}

	savedFingerprint := keygen.GetFingerprintFromCert(cert)
	checkFingerprint, err := c.CheckServer(fmt.Sprintf("%s:%v", hostname, c.conf.Port))
	if err != nil {
		return false
	}

	return savedFingerprint == checkFingerprint
}

func (c *Client) GetTrustedClient(hostname string) (*http.Client, error) {
	certPath := fmt.Sprintf("%s/%s-cert.pem", c.conf.TrustedCertsDir, hostname)
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

func (c *Client) GetSavedFingerprint(hostname string) string {
	certPath := fmt.Sprintf("%s/%s-cert.pem", c.conf.TrustedCertsDir, hostname)
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

func (c *Client) UploadFile(hostname string, path string) error {
	return nil
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
