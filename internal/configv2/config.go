package configv2

import (
	"fmt"
	"os"
	"strings"
)

type Config struct {
	DatabaseURL        string
	Listen             string
	Mode               string
	AdminFile          string
	Origin             string
	TLSCert            string
	TLSKey             string
	FixtureAuthorities []string
	DeliveryEndpoint   string
	AIKeyFile          string
	AICAFile           string
	AIAuthorities      []string
	AutomaticInference bool
	ManualInference    bool
}

// Load reads a secret file reference, never the legacy configuration or LLM variables.
func Load(mode, listen, dbRef string) (Config, error) {
	if mode != "api" && mode != "worker" && mode != "collector" {
		return Config{}, fmt.Errorf("invalid v2 mode")
	}
	if dbRef == "" {
		return Config{}, fmt.Errorf("database secret file reference required")
	}
	b, err := os.ReadFile(dbRef)
	if err != nil {
		return Config{}, fmt.Errorf("cannot read database secret file")
	}
	dsn := strings.TrimSpace(string(b))
	if dsn == "" {
		return Config{}, fmt.Errorf("empty database secret file")
	}
	return Config{DatabaseURL: dsn, Listen: listen, Mode: mode}, nil
}
