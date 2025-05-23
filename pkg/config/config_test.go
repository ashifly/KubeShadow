package config

import (
	"encoding/json"
	"kubeshadow/pkg/errors"
	"kubeshadow/pkg/testutil"
	"os"
	"testing"
)

func TestConfigManager(t *testing.T) {
	tests := []struct {
		name      string
		config    string
		wantError bool
	}{
		{
			name: "Valid configuration",
			config: `{
				"log_level": "info",
				"modules": {
					"sidecar": {
						"enabled": true,
						"config": {
							"image": "test-image:latest"
						}
					}
				}
			}`,
			wantError: false,
		},
		{
			name:      "Empty configuration",
			config:    `{}`,
			wantError: false,
		},
		{
			name:      "Invalid JSON",
			config:    `{invalid json}`,
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			configPath := testutil.CreateTempConfig(t, tt.config)
			manager := NewConfigManager()
			err := manager.LoadConfig(configPath)

			if (err != nil) != tt.wantError {
				t.Errorf("LoadConfig() error = %v, wantError %v", err, tt.wantError)
			}

			if err != nil && !errors.IsConfigError(err) {
				t.Errorf("Expected config error, got %v", err)
			}
		})
	}
}

func TestGetModuleConfig(t *testing.T) {
	config := `{
		"modules": {
			"sidecar": {
				"enabled": true,
				"config": {
					"image": "test-image:latest"
				}
			}
		}
	}`

	configPath := testutil.CreateTempConfig(t, config)
	manager := NewConfigManager()
	if err := manager.LoadConfig(configPath); err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	tests := []struct {
		name      string
		module    string
		wantError bool
	}{
		{
			name:      "Existing module",
			module:    "sidecar",
			wantError: false,
		},
		{
			name:      "Non-existent module",
			module:    "nonexistent",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			moduleConfig, err := manager.GetModuleConfig(tt.module)

			if (err != nil) != tt.wantError {
				t.Errorf("GetModuleConfig() error = %v, wantError %v", err, tt.wantError)
			}

			if err != nil && !errors.IsConfigError(err) {
				t.Errorf("Expected config error, got %v", err)
			}

			if !tt.wantError && moduleConfig == nil {
				t.Error("Expected module config to be non-nil")
			}
		})
	}
}

func TestGetConfig(t *testing.T) {
	config := `{
		"log_level": "info",
		"modules": {
			"sidecar": {
				"enabled": true
			}
		}
	}`

	configPath := testutil.CreateTempConfig(t, config)
	manager := NewConfigManager()
	if err := manager.LoadConfig(configPath); err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	cfg, err := manager.GetConfig()
	if err != nil {
		t.Errorf("GetConfig() error = %v", err)
	}

	if cfg == nil {
		t.Error("Expected config to be non-nil")
	}

	if logLevel, ok := cfg["log_level"].(string); !ok || logLevel != "info" {
		t.Errorf("Expected log_level to be 'info', got %v", logLevel)
	}
}

func NewConfigManager() *ConfigManager {
	return &ConfigManager{
		config: make(map[string]interface{}),
	}
}

type ConfigManager struct {
	config map[string]interface{}
}

func (m *ConfigManager) LoadConfig(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return errors.New(errors.ErrConfig, "failed to read config file", err)
	}
	if err := json.Unmarshal(data, &m.config); err != nil {
		return errors.New(errors.ErrConfig, "failed to parse config file", err)
	}
	return nil
}

func (m *ConfigManager) GetConfig() (map[string]interface{}, error) {
	if m.config == nil {
		return nil, errors.New(errors.ErrConfig, "config not loaded", nil)
	}
	return m.config, nil
}

func (m *ConfigManager) GetModuleConfig(moduleName string) (map[string]interface{}, error) {
	if m.config == nil {
		return nil, errors.New(errors.ErrConfig, "config not loaded", nil)
	}
	modules, ok := m.config["modules"].(map[string]interface{})
	if !ok {
		return nil, errors.New(errors.ErrConfig, "invalid modules configuration", nil)
	}
	moduleConfig, ok := modules[moduleName].(map[string]interface{})
	if !ok {
		return nil, errors.New(errors.ErrConfig, "module not found", nil)
	}
	return moduleConfig, nil
}
