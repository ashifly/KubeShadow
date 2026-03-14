package types

import (
	"context"
)

// Plugin defines the interface that all plugins must implement
type Plugin interface {
	// Name returns the unique name of the plugin
	Name() string

	// Version returns the plugin version
	Version() string

	// Initialize is called when the plugin is loaded
	Initialize(ctx context.Context) error

	// Execute runs the plugin's main functionality
	Execute(ctx context.Context) error

	// Cleanup is called when the plugin is unloaded
	Cleanup(ctx context.Context) error

	// GetStatus returns the current status of the plugin
	GetStatus() *PluginStatus
}

// PluginStatus represents the current state of a plugin
type PluginStatus struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Status  string `json:"status"`
	Error   string `json:"error,omitempty"`
}

// PluginConfig represents the configuration for a plugin
type PluginConfig struct {
	Enabled bool                   `json:"enabled"`
	Config  map[string]interface{} `json:"config"`
}

// PluginRegistry manages the lifecycle of plugins
type PluginRegistry interface {
	// RegisterPlugin registers a new plugin
	RegisterPlugin(plugin Plugin) error

	// GetPlugin retrieves a plugin by name
	GetPlugin(name string) (Plugin, error)

	// ListPlugins returns all registered plugins
	ListPlugins() []Plugin

	// UnregisterPlugin removes a plugin from the registry
	UnregisterPlugin(name string) error

	// GetPluginStatus returns the status of a specific plugin
	GetPluginStatus(name string) (*PluginStatus, error)
}
