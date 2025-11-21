package server

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/nielsjaspers/clifs/internal/config"
)

type Server struct {
	conf config.Config
}

func NewServer(conf config.Config) *Server {
	return &Server{conf: conf}
}

func (s *Server) HandleServer() {
	certFile := s.conf.CertPath
	keyFile := s.conf.KeyPath

	http.HandleFunc("/", s.HelloServer)
	http.HandleFunc("/upload", s.handleUpload)

	server := &http.Server{
		Addr:      fmt.Sprintf(":%d", s.conf.Port),
		TLSConfig: &tls.Config{},
	}

	log.Printf("Starting server on port %d...\n", s.conf.Port)
	err := server.ListenAndServeTLS(certFile, keyFile)
	if err != nil {
		log.Fatalf("Error starting server: %v\n", err)
	}
}

func (s *Server) HelloServer(w http.ResponseWriter, req *http.Request) {
	fmt.Fprintf(w, "Hello, %s!", req.URL.Path[1:])
}

func (s *Server) handleUpload(w http.ResponseWriter, r *http.Request) {
	// Only allow POST requests
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse multipart form (up to 32MB)
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		http.Error(w, "Failed to parse form", http.StatusBadRequest)
		return
	}

	// Get file from request
	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "Failed to get file", http.StatusBadRequest)
		return
	}
	defer file.Close()

	timestamp := time.Now().Format("2006-01-02_15-04-05")
	fileName := timestamp + header.Filename
	safeFilename := filepath.Clean(fileName)

	// Create the destination file
	dst, err := os.Create(filepath.Join(s.conf.UploadDir, safeFilename))
	if err != nil {
		http.Error(w, "Failed to create file: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer dst.Close()

	// Copy the file data
	if _, err := io.Copy(dst, file); err != nil {
		http.Error(w, "Failed to save file: "+err.Error(), http.StatusInternalServerError)
		return
	}
	log.Printf("Received file: %s (size: %d bytes)\n", header.Filename, header.Size)
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "File uploaded successfully: %s", safeFilename)
}
