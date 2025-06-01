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
	ModuleConfig map[string]interface{} `yaml:"module_config"`

	// Global configuration
	GlobalConfig GlobalConfig `yaml:"global_config"`
}

// GlobalConfig represents the global configuration settings
type GlobalConfig struct {
	KubeConfig string `yaml:"kubeconfig"`
	Stealth    bool   `yaml:"stealth"`
	Debug      bool   `yaml:"debug"`
}

// LoadConfig loads configuration from file
func LoadConfig(configPath string) (*Config, error) {
	// Validate config path
	if !filepath.IsAbs(configPath) {
		return nil, fmt.Errorf("config path must be absolute: %s", configPath)
	}

	// Ensure file exists and is readable
	if _, err := os.Stat(configPath); err != nil {
		return nil, fmt.Errorf("failed to access config file: %v", err)
	}

	// Read config file
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %v", err)
	}

	config := &Config{
		ModuleConfig: make(map[string]interface{}),
		GlobalConfig: GlobalConfig{},
	}

	if err := yaml.Unmarshal(data, config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %v", err)
	}

	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %v", err)
	}

	return config, nil
}

// SaveConfig saves configuration to file
func SaveConfig(config *Config, configPath string) error {
	// Validate config path
	if !filepath.IsAbs(configPath) {
		return fmt.Errorf("config path must be absolute: %s", configPath)
	}

	// Ensure directory exists
	dir := filepath.Dir(configPath)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return fmt.Errorf("failed to create config directory: %v", err)
	}

	// Marshal config
	data, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %v", err)
	}

	// Write config file with secure permissions
	if err := os.WriteFile(configPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write config file: %v", err)
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
