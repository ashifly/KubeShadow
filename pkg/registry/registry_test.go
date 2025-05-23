package registry

import (
	"kubeshadow/pkg/errors"
	"kubeshadow/pkg/modules/sidecar"
	"testing"
)

func TestModuleRegistry(t *testing.T) {
	// Create a new registry
	registry := NewModuleRegistry()

	// Test registering a module
	sidecarModule := sidecar.NewSidecarModule()
	err := registry.RegisterModule(sidecarModule)
	if err != nil {
		t.Errorf("Failed to register module: %v", err)
	}

	// Test getting a registered module
	module, err := registry.GetModule("sidecar")
	if err != nil {
		t.Errorf("Failed to get module: %v", err)
	}
	if module == nil {
		t.Error("Expected module to be non-nil")
	}

	// Test getting a non-existent module
	_, err = registry.GetModule("nonexistent")
	if err == nil {
		t.Error("Expected error when getting non-existent module")
	}
	if !errors.IsModuleError(err) {
		t.Error("Expected module error type")
	}

	// Test registering duplicate module
	err = registry.RegisterModule(sidecarModule)
	if err == nil {
		t.Error("Expected error when registering duplicate module")
	}
	if !errors.IsModuleError(err) {
		t.Error("Expected module error type")
	}

	// Test listing modules
	modules := registry.ListModules()
	if len(modules) != 1 {
		t.Errorf("Expected 1 module, got %d", len(modules))
	}
	if modules[0] != "sidecar" {
		t.Errorf("Expected module name 'sidecar', got %s", modules[0])
	}
}
