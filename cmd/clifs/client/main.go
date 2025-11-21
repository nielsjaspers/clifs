package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/nielsjaspers/clifs/internal/client"
	"github.com/nielsjaspers/clifs/internal/config"
)

func main() {
	host := flag.String("host", "", "Server host")
	port := flag.Int("port", 443, "Server port")
	checkServer := flag.Bool("check", false, "Check if the server is reachable")
	trustServer := flag.Bool("trust", false, "Trust the server")
	path := flag.String("path", "", "Path to file to upload")
	flag.Parse()

	clientConfig := config.Config{
		ServerHost:      *host,
		Port:            *port,
		TrustedCertsDir: config.GetConfigDir(),
	}

	c := client.NewClient(clientConfig)

	if *checkServer {
		fingerprint, err := c.CheckServer(fmt.Sprintf("%s:%d", *host, *port))
		if err != nil {
			log.Fatalf("Server check failed: %v", err)
		}
		fmt.Printf("Server is reachable at %s:%d\n", *host, *port)
		fmt.Printf("Server certificate fingerprint: %s\n", fingerprint)

		// Check if we already trust this server
		trusted := c.IsServerTrusted(*host)
		if trusted {
			fmt.Println("This server is already trusted.")
		} else {
			fmt.Println("This server is NOT trusted. Use the -trust flag to trust it.")
		}
		return
	}

	if *trustServer {
		err := c.TrustServer(fmt.Sprintf("%s:%d", *host, *port))
		if err != nil {
			log.Fatalf("Failed to trust server: %v", err)
		}
		fmt.Println("Server trusted successfully!")
		return
	}

	if *path != "" {
		err := c.UploadFile(fmt.Sprintf("%s:%d", *host, *port), *path)
		if err != nil {
			log.Fatalf("Failed to upload file: %v", err)
		}
		fmt.Println("File uploaded successfully!")
		return
	}
}
