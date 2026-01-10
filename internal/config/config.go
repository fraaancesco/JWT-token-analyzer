package config

import (
	"os"
	"strconv"
	"time"
)

// Config holds the application configuration
type Config struct {
	Server  ServerConfig
	Analyzer AnalyzerConfig
}

// ServerConfig holds server-related configuration
type ServerConfig struct {
	Port    string
	GinMode string
}

// AnalyzerConfig holds analyzer-related configuration
type AnalyzerConfig struct {
	CheckExpiration    bool
	MaxTokenLifetime   time.Duration
	WarnTokenLifetime  time.Duration
}

// Load loads configuration from environment variables
func Load() *Config {
	return &Config{
		Server: ServerConfig{
			Port:    getEnv("SERVER_PORT", "8082"),
			GinMode: getEnv("GIN_MODE", "debug"),
		},
		Analyzer: AnalyzerConfig{
			CheckExpiration:    getBoolEnv("ANALYZER_CHECK_EXPIRATION", true),
			MaxTokenLifetime:   getDurationEnv("ANALYZER_MAX_TOKEN_LIFETIME", 168*time.Hour),
			WarnTokenLifetime:  getDurationEnv("ANALYZER_WARN_TOKEN_LIFETIME", 24*time.Hour),
		},
	}
}

func getEnv(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}

func getBoolEnv(key string, defaultValue bool) bool {
	if value, exists := os.LookupEnv(key); exists {
		if parsed, err := strconv.ParseBool(value); err == nil {
			return parsed
		}
	}
	return defaultValue
}

func getDurationEnv(key string, defaultValue time.Duration) time.Duration {
	if value, exists := os.LookupEnv(key); exists {
		if hours, err := strconv.Atoi(value); err == nil {
			return time.Duration(hours) * time.Hour
		}
	}
	return defaultValue
}
