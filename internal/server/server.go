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

	"github.com/nielsjaspers/clifs/internal/keygen"
)

func HandleServer() {
	// TODO: Change key generation to flag instead on every start
	err := keygen.GenerateKeys()
	if err != nil {
		log.Fatalf("Error creating keys: %v\n", err)
	}

	certFile := "server-env/cert.pem"
	keyFile := "server-env/key.pem"

	http.HandleFunc("/", HelloServer)
	http.HandleFunc("/upload", handleUpload)

	server := &http.Server{
		Addr:      ":443",
		TLSConfig: &tls.Config{},
	}

	log.Println("Starting server on port 443...")
	err = server.ListenAndServeTLS(certFile, keyFile)
	if err != nil {
		log.Fatalf("Error starting server: %v\n", err)
	}
}

func HelloServer(w http.ResponseWriter, req *http.Request) {
	fmt.Fprintf(w, "Hello, %s!", req.URL.Path[1:])
}

func handleUpload(w http.ResponseWriter, r *http.Request) {
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
	// TODO: change to use config.UploadDir
	dst, err := os.Create(filepath.Join("./uploads", safeFilename))
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
	log.Printf("Received file: %s (size: %d bytes)", header.Filename, header.Size)
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "File uploaded successfully: %s", safeFilename)
}
