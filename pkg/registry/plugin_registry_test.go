package registry

import (
	"context"
	"kubeshadow/pkg/types"
	"testing"
)

// mockPlugin implements the Plugin interface for testing
type mockPlugin struct {
	name    string
	version string
	status  string
	err     string
}

func (m *mockPlugin) Name() string    { return m.name }
func (m *mockPlugin) Version() string { return m.version }
func (m *mockPlugin) Initialize(ctx context.Context) error {
	if m.err != "" {
		return nil
	}
	return nil
}
func (m *mockPlugin) Execute(ctx context.Context) error {
	if m.err != "" {
		return nil
	}
	return nil
}
func (m *mockPlugin) Cleanup(ctx context.Context) error {
	if m.err != "" {
		return nil
	}
	return nil
}
func (m *mockPlugin) GetStatus() *types.PluginStatus {
	return &types.PluginStatus{
		Name:    m.name,
		Version: m.version,
		Status:  m.status,
		Error:   m.err,
	}
}

func TestPluginRegistry(t *testing.T) {
	registry := NewPluginRegistry()

	// Test plugin
	plugin := &mockPlugin{
		name:    "test-plugin",
		version: "1.0.0",
		status:  "running",
	}

	t.Run("RegisterPlugin", func(t *testing.T) {
		// Test successful registration
		err := registry.RegisterPlugin(plugin)
		if err != nil {
			t.Errorf("RegisterPlugin() error = %v", err)
		}

		// Test duplicate registration
		err = registry.RegisterPlugin(plugin)
		if err == nil {
			t.Error("RegisterPlugin() expected error for duplicate plugin")
		}
	})

	t.Run("GetPlugin", func(t *testing.T) {
		// Test successful retrieval
		p, err := registry.GetPlugin("test-plugin")
		if err != nil {
			t.Errorf("GetPlugin() error = %v", err)
		}
		if p.Name() != plugin.Name() {
			t.Errorf("GetPlugin() got = %v, want %v", p.Name(), plugin.Name())
		}

		// Test non-existent plugin
		_, err = registry.GetPlugin("non-existent")
		if err == nil {
			t.Error("GetPlugin() expected error for non-existent plugin")
		}
	})

	t.Run("ListPlugins", func(t *testing.T) {
		plugins := registry.ListPlugins()
		if len(plugins) != 1 {
			t.Errorf("ListPlugins() got %d plugins, want 1", len(plugins))
		}
		if plugins[0].Name() != plugin.Name() {
			t.Errorf("ListPlugins() got = %v, want %v", plugins[0].Name(), plugin.Name())
		}
	})

	t.Run("GetPluginStatus", func(t *testing.T) {
		// Test successful status retrieval
		status, err := registry.GetPluginStatus("test-plugin")
		if err != nil {
			t.Errorf("GetPluginStatus() error = %v", err)
		}
		if status.Name != plugin.Name() {
			t.Errorf("GetPluginStatus() got = %v, want %v", status.Name, plugin.Name())
		}

		// Test non-existent plugin
		_, err = registry.GetPluginStatus("non-existent")
		if err == nil {
			t.Error("GetPluginStatus() expected error for non-existent plugin")
		}
	})

	t.Run("UnregisterPlugin", func(t *testing.T) {
		// Test successful unregistration
		err := registry.UnregisterPlugin("test-plugin")
		if err != nil {
			t.Errorf("UnregisterPlugin() error = %v", err)
		}

		// Test non-existent plugin
		err = registry.UnregisterPlugin("test-plugin")
		if err == nil {
			t.Error("UnregisterPlugin() expected error for non-existent plugin")
		}
	})
}
