package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/nielsjaspers/clifs/internal/config"
	"github.com/nielsjaspers/clifs/internal/keygen"
	"github.com/nielsjaspers/clifs/internal/server"
)

func main() {
	port := flag.Int("port", 443, "Port to listen on")
	uploadDir := flag.String("upload-dir", "uploads", "Directory to upload files to")
	genCert := flag.Bool("gen-cert", false, "Generate a new self-signed certificate")
	flag.Parse()

	// Make sure upload directory exists
	if err := os.MkdirAll(*uploadDir, 0755); err != nil {
		log.Fatalf("Failed to create upload directory: %v", err)
	}

	conf := config.Config{
		Port:      *port,
		UploadDir: *uploadDir,
		CertPath:  filepath.Join(config.GetConfigDir(), "cert.pem"),
		KeyPath:   filepath.Join(config.GetConfigDir(), "key.pem"),
	}

	// Generate certificates if requested or if they don't exist
	if *genCert || !keygen.CertificatesExist(conf.CertPath, conf.KeyPath) {
		fmt.Println("Generating new self-signed certificate...")
		if err := keygen.GenerateKeys(); err != nil {
			log.Fatalf("Failed to generate certificates: %v", err)
		}
		fmt.Println("Certificates generated successfully!")
	}

	fmt.Printf("Starting server on port %d\n", conf.Port)
	fmt.Printf("Files will be stored in: %s\n", conf.UploadDir)
	fmt.Printf("Server fingerprint: %s\n", keygen.GetFingerprint(conf.CertPath))

	server := server.NewServer(conf)
	server.HandleServer()
}
