package config

import (
	"testing"
	"time"
)

func TestLoadDefaults(t *testing.T) {
	for _, key := range []string{"SERVER_PORT", "GIN_MODE", "ANALYZER_CHECK_EXPIRATION", "ANALYZER_MAX_TOKEN_LIFETIME", "ANALYZER_WARN_TOKEN_LIFETIME"} {
		t.Setenv(key, "")
	}
	// t.Setenv cannot unset: invalid empty values must fall back to the defaults,
	// except for the plain strings, which are taken as they are.
	cfg := Load()
	if cfg.Analyzer.CheckExpiration != true {
		t.Error("CheckExpiration should default to true")
	}
	if cfg.Analyzer.MaxTokenLifetime != 168*time.Hour {
		t.Errorf("MaxTokenLifetime = %v", cfg.Analyzer.MaxTokenLifetime)
	}
	if cfg.Analyzer.WarnTokenLifetime != 24*time.Hour {
		t.Errorf("WarnTokenLifetime = %v", cfg.Analyzer.WarnTokenLifetime)
	}
}

func TestLoadUnsetVariables(t *testing.T) {
	cfg := Load()
	if cfg.Server.Port != "8082" || cfg.Server.GinMode != "debug" {
		t.Errorf("unexpected server defaults: %+v", cfg.Server)
	}
}

func TestLoadFromEnvironment(t *testing.T) {
	t.Setenv("SERVER_PORT", "9000")
	t.Setenv("GIN_MODE", "release")
	t.Setenv("ANALYZER_CHECK_EXPIRATION", "false")
	t.Setenv("ANALYZER_MAX_TOKEN_LIFETIME", "48")
	t.Setenv("ANALYZER_WARN_TOKEN_LIFETIME", "2")

	cfg := Load()
	if cfg.Server.Port != "9000" || cfg.Server.GinMode != "release" {
		t.Errorf("unexpected server config: %+v", cfg.Server)
	}
	if cfg.Analyzer.CheckExpiration {
		t.Error("CheckExpiration should be false")
	}
	if cfg.Analyzer.MaxTokenLifetime != 48*time.Hour || cfg.Analyzer.WarnTokenLifetime != 2*time.Hour {
		t.Errorf("unexpected lifetimes: %+v", cfg.Analyzer)
	}
}

func TestLoadInvalidValues(t *testing.T) {
	t.Setenv("ANALYZER_CHECK_EXPIRATION", "maybe")
	t.Setenv("ANALYZER_MAX_TOKEN_LIFETIME", "a week")

	cfg := Load()
	if !cfg.Analyzer.CheckExpiration || cfg.Analyzer.MaxTokenLifetime != 168*time.Hour {
		t.Errorf("invalid values should fall back to defaults: %+v", cfg.Analyzer)
	}
}
