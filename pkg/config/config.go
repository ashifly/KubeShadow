package config

import (
	"encoding/json"
	"os"
)

// Config represents the module configuration
type Config struct {
	// Module-specific configuration
	ModuleConfig map[string]interface{} `json:"module_config"`

	// Global configuration
	GlobalConfig struct {
		KubeConfig string `json:"kubeconfig"`
		Stealth    bool   `json:"stealth"`
		Debug      bool   `json:"debug"`
	} `json:"global_config"`
}

// LoadConfig loads configuration from file
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	return &config, nil
}

// SaveConfig saves configuration to file
func SaveConfig(config *Config, path string) error {
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0644)
}
