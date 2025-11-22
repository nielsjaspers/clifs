package server

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"mime/multipart"
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
	http.HandleFunc("/upload", s.handleConcurrentUpload)

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

func (s *Server) handleConcurrentUpload(w http.ResponseWriter, r *http.Request) {
	// Only allow POST requests
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Allow up to 32 MB for all files total
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		http.Error(w, "Failed to parse form", http.StatusBadRequest)
		return
	}

	// Get files from the request under 'file' or 'files'
	form := r.MultipartForm
	files := form.File["file"]
	if len(files) == 0 {
		files = form.File["files"]
	}
	if len(files) == 0 {
		http.Error(w, "No files found in upload", http.StatusBadRequest)
		return
	}

	// Channel for status and done
	type uploadResult struct {
		Filename string
		SavedAs  string
		Size     int64
		Err      error
	}

	results := make(chan uploadResult, len(files))

	for _, header := range files {
		// For each file header, start a goroutine that saves the file concurrently
		go func(header *multipart.FileHeader) {
			file, err := header.Open()
			if err != nil {
				results <- uploadResult{Filename: header.Filename, Err: err}
				return
			}
			defer file.Close()

			timestamp := time.Now().Format("2006-01-02_15-04-05")
			fileName := timestamp + header.Filename
			safeFilename := filepath.Clean(fileName)

			dstPath := filepath.Join(s.conf.UploadDir, safeFilename)
			dst, err := os.Create(dstPath)
			if err != nil {
				results <- uploadResult{Filename: header.Filename, Err: err}
				return
			}
			defer dst.Close()

			size, err := io.Copy(dst, file)
			if err != nil {
				results <- uploadResult{Filename: header.Filename, Err: err}
				return
			}

			results <- uploadResult{
				Filename: header.Filename,
				SavedAs:  safeFilename,
				Size:     size,
				Err:      nil,
			}
		}(header)
	}

	var savedFiles []string
	var errors []string

	for i := 0; i < len(files); i++ {
		res := <-results
		if res.Err != nil {
			errors = append(errors, fmt.Sprintf("Failed to save %s: %v", res.Filename, res.Err))
			log.Printf("Failed to receive file: %s, err: %v\n", res.Filename, res.Err)
		} else {
			savedFiles = append(savedFiles, res.SavedAs)
			log.Printf("Received file: %s (size: %d bytes)\n", res.Filename, res.Size)
		}
	}

	if len(errors) > 0 {
		http.Error(w, "Errors occurred: "+fmt.Sprintf("%v", errors), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Files uploaded successfully: %v", savedFiles)
}
