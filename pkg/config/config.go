package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
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
func LoadConfig(configPath string) (*Config, error) {
	if !filepath.IsAbs(configPath) {
		return nil, fmt.Errorf("config path must be absolute: %s", configPath)
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file %s: %v", configPath, err)
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %v", err)
	}

	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %v", err)
	}

	return &config, nil
}

// SaveConfig saves configuration to file
func SaveConfig(config *Config, path string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("config path must be absolute: %s", path)
	}

	data, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %v", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("failed to write config file %s: %v", path, err)
	}

	return nil
}

func (c *Config) Validate() error {
	if c.GlobalConfig.KubeConfig == "" {
		return fmt.Errorf("kubernetes configuration is required")
	}

	if c.GlobalConfig.KubeConfig == "" {
		return fmt.Errorf("kubernetes API server URL is required")
	}

	if c.GlobalConfig.KubeConfig == "" {
		return fmt.Errorf("kubernetes namespace is required")
	}

	if c.GlobalConfig.KubeConfig == "" {
		return fmt.Errorf("etcd configuration is required")
	}

	if c.GlobalConfig.KubeConfig == "" {
		return fmt.Errorf("at least one etcd endpoint is required")
	}

	if c.GlobalConfig.KubeConfig != "" {
		if _, err := os.Stat(c.GlobalConfig.KubeConfig); err != nil {
			return fmt.Errorf("invalid CA file path: %v", err)
		}
	}

	if c.GlobalConfig.KubeConfig != "" {
		if _, err := os.Stat(c.GlobalConfig.KubeConfig); err != nil {
			return fmt.Errorf("invalid cert file path: %v", err)
		}
	}

	if c.GlobalConfig.KubeConfig != "" {
		if _, err := os.Stat(c.GlobalConfig.KubeConfig); err != nil {
			return fmt.Errorf("invalid key file path: %v", err)
		}
	}

	return nil
}
