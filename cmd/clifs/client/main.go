package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/nielsjaspers/clifs/internal/client"
	"github.com/nielsjaspers/clifs/internal/config"
)

// StringSlice is a custom flag type that accepts multiple string values
type StringSlice []string

func (s *StringSlice) String() string {
	return strings.Join(*s, ",")
}

func (s *StringSlice) Set(value string) error {
	*s = append(*s, value)
	return nil
}

func main() {
	host := flag.String("host", "", "Server host")
	port := flag.Int("port", 443, "Server port")
	checkServer := flag.Bool("check", false, "Check if the server is reachable")
	trustServer := flag.Bool("trust", false, "Trust the server")
	var paths StringSlice
	flag.Var(&paths, "path", "Path to file(s) to upload (can specify multiple files)")

	// Custom parsing to support -path fileA fileB fileC syntax
	args := os.Args[1:]
	var parsedArgs []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "-path" || arg == "--path" {
			// Consume all following arguments until we hit another flag
			for i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				i++
				parsedArgs = append(parsedArgs, "-path", args[i])
			}
		} else {
			parsedArgs = append(parsedArgs, arg)
		}
	}

	// Parse the modified args
	os.Args = append([]string{os.Args[0]}, parsedArgs...)
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

	if len(paths) > 0 {
		err := c.UploadFile(fmt.Sprintf("%s:%d", *host, *port), paths...)
		if err != nil {
			log.Fatalf("Failed to upload file: %v", err)
		}
		fmt.Println("File uploaded successfully!")
		return
	}
}
