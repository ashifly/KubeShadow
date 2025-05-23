package types

import (
	"context"

	"github.com/spf13/cobra"
)

// Module represents a KubeShadow module that can be registered and executed
type Module interface {
	// Name returns the unique identifier for this module
	Name() string

	// Description returns a brief description of what the module does
	Description() string

	// Command returns the cobra command for this module
	Command() *cobra.Command

	// Validate performs validation of the module's configuration
	Validate() error

	// Execute runs the module's main logic
	Execute(ctx context.Context) error

	// Cleanup performs any necessary cleanup when the module is done
	Cleanup() error
}

// ModuleConfig represents the configuration for a module
type ModuleConfig struct {
	Enabled bool                   `json:"enabled"`
	Config  map[string]interface{} `json:"config"`
}

// ModuleStatus represents the current status of a module
type ModuleStatus struct {
	Name      string `json:"name"`
	Status    string `json:"status"` // "running", "stopped", "error"
	Error     string `json:"error,omitempty"`
	StartTime string `json:"startTime,omitempty"`
	EndTime   string `json:"endTime,omitempty"`
}

// BaseModule provides a base implementation of the Module interface
type BaseModule struct {
	name        string
	description string
	Cmd         *cobra.Command
}

// NewBaseModule creates a new base module
func NewBaseModule(name, description string) *BaseModule {
	return &BaseModule{
		name:        name,
		description: description,
	}
}

// Name implements Module interface
func (m *BaseModule) Name() string {
	return m.name
}

// Description implements Module interface
func (m *BaseModule) Description() string {
	return m.description
}

// Command implements Module interface
func (m *BaseModule) Command() *cobra.Command {
	return m.Cmd
}
