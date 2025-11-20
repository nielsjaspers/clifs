package server

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"

	"github.com/nielsjaspers/clifs/internal/keygen"
)

func HandleServer() {
	err := keygen.GenerateKeys()
	if err != nil {
		log.Fatalf("Error creating keys: %v\n", err)
	}

	certFile := "server-env/cert.pem"
	keyFile := "server-env/key.pem"

	http.HandleFunc("/", HelloServer)

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
