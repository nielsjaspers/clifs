package client

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"

	"github.com/nielsjaspers/clifs/internal/config"
	"github.com/nielsjaspers/clifs/internal/keygen"
)

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

// GetTrustedClient returns an http.Client that uses the trusted certificate
// for the given hostname. If the certificate is not trusted, it returns an
// error.
//
// hostname: the hostname of the server to get the client for.
//
// Returns:
//
// *http.Client: an http.Client that uses the trusted certificate for the given hostname.
//
// error: an error if the certificate is not trusted.
func (c *Client) GetTrustedClient(hostname string) (*http.Client, error) {
	caPool, err := c.GetTrustedCaPool(hostname)
	if err != nil {
		return nil, err
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs: caPool,
		},
	}

	return &http.Client{Transport: tr}, nil
}

// GetTrustedCaPool returns an x509.CertPool that contains the trusted
// certificate for the given hostname. If the certificate is not trusted,
// it returns an error.
//
// hostname: the hostname of the server to get the caPool for.
//
// Returns:
//
// *x509.CertPool: an x509.CertPool that contains the trusted certificate for the given hostname.
//
// error: an error if the certificate is not trusted.
func (c *Client) GetTrustedCaPool(hostname string) (*x509.CertPool, error) {
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

	return caPool, nil
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

func (c *Client) UploadFile(hostname string, paths ...string) error {
	if len(paths) == 0 {
		return fmt.Errorf("no file paths provided")
	}

	caPool, err := c.GetTrustedCaPool(hostname)
	if err != nil {
		return fmt.Errorf("failed to get trusted ca pool: %v", err)
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs: caPool,
		},
	}
	httpClient := &http.Client{Transport: tr}

	// Create a new form data buffer
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	// Add each file to the multipart form
	for _, path := range paths {
		file, err := os.Open(path)
		if err != nil {
			writer.Close()
			return fmt.Errorf("failed to open file %s: %v", path, err)
		}

		// Create a form file field and add the file
		part, err := writer.CreateFormFile("file", filepath.Base(path))
		if err != nil {
			file.Close()
			writer.Close()
			return fmt.Errorf("failed to create form file for %s: %w", path, err)
		}

		// Copy the file data to the form
		if _, err = io.Copy(part, file); err != nil {
			file.Close()
			writer.Close()
			return fmt.Errorf("failed to copy file data for %s: %w", path, err)
		}

		file.Close()
	}

	// Close the multipart writer to finalize the body
	err = writer.Close()
	if err != nil {
		return fmt.Errorf("failed to close multipart writer: %w", err)
	}

	// Create the request
	url := fmt.Sprintf("https://%s/upload", hostname)
	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set the content type to the multipart form boundary
	req.Header.Set("Content-Type", writer.FormDataContentType())

	// Send the request
	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Check for successful upload
	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server returned error: %s (%d)", string(bodyBytes), resp.StatusCode)
	}
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
