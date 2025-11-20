package config

import (
	"os"
	"path/filepath"
)

type Config struct {
	// Server Configuration
	Port      int
	UploadDir string
	CertPath  string
	KeyPath   string

	// Client Configuration
	ServerHost      string
	TrustedCertsDir string
}

func GetConfigDir() string {
	configDir := os.Getenv("XDG_CONFIG_HOME")
	if configDir != "" {
		return filepath.Join(configDir, "clifs")
	}
	// Fall back to platform-specific home directory
	homeDir, err := os.UserHomeDir()
	if err != nil {
		// If we can't determine home directory, use current directory
		return ".clifs"
	}

	// On most systems, use ~/.config/clifs
	return filepath.Join(homeDir, ".config", "clifs")
}
