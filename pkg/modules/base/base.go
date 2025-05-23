package base

import (
	"context"
	"fmt"
	"kubeshadow/pkg/logger"
	"kubeshadow/pkg/types"
	"time"

	"github.com/spf13/cobra"
)

// BaseModule provides a base implementation of the Module interface
type BaseModule struct {
	name        string
	description string
	cmd         *cobra.Command
	config      *types.ModuleConfig
	status      *types.ModuleStatus
}

// NewBaseModule creates a new base module with the given name and description
func NewBaseModule(name, description string) *BaseModule {
	return &BaseModule{
		name:        name,
		description: description,
		status: &types.ModuleStatus{
			Name:   name,
			Status: "stopped",
		},
	}
}

// Name returns the module name
func (m *BaseModule) Name() string {
	return m.name
}

// Description returns the module description
func (m *BaseModule) Description() string {
	return m.description
}

// Command returns the cobra command
func (m *BaseModule) Command() *cobra.Command {
	return m.cmd
}

// SetCommand sets the cobra command for the module
func (m *BaseModule) SetCommand(cmd *cobra.Command) {
	m.cmd = cmd
}

// SetConfig sets the module configuration
func (m *BaseModule) SetConfig(config *types.ModuleConfig) {
	m.config = config
}

// GetConfig returns the module configuration
func (m *BaseModule) GetConfig() *types.ModuleConfig {
	return m.config
}

// GetStatus returns the current module status
func (m *BaseModule) GetStatus() *types.ModuleStatus {
	return m.status
}

// Validate performs basic validation of the module configuration
func (m *BaseModule) Validate() error {
	if m.config == nil {
		return fmt.Errorf("module configuration is required")
	}
	if !m.config.Enabled {
		return fmt.Errorf("module is disabled")
	}
	return nil
}

// Execute provides a base implementation that updates the module status
func (m *BaseModule) Execute(ctx context.Context) error {
	m.status.Status = "running"
	m.status.StartTime = time.Now().Format(time.RFC3339)
	m.status.Error = ""

	defer func() {
		m.status.Status = "stopped"
		m.status.EndTime = time.Now().Format(time.RFC3339)
	}()

	logger.Info("Starting %s module", m.name)
	return nil
}

// Cleanup provides a base implementation for cleanup
func (m *BaseModule) Cleanup() error {
	logger.Info("Cleaning up %s module", m.name)
	return nil
}

// UpdateStatus updates the module status
func (m *BaseModule) UpdateStatus(status string, err error) {
	m.status.Status = status
	if err != nil {
		m.status.Error = err.Error()
	} else {
		m.status.Error = ""
	}
}
