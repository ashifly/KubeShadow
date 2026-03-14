package registry

import (
	"fmt"
	"kubeshadow/pkg/errors"
	"kubeshadow/pkg/types"
	"sync"
)

// pluginRegistry implements the PluginRegistry interface
type pluginRegistry struct {
	plugins map[string]types.Plugin
	mu      sync.RWMutex
}

// NewPluginRegistry creates a new plugin registry
func NewPluginRegistry() types.PluginRegistry {
	return &pluginRegistry{
		plugins: make(map[string]types.Plugin),
	}
}

// RegisterPlugin registers a new plugin
func (r *pluginRegistry) RegisterPlugin(plugin types.Plugin) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	name := plugin.Name()
	if _, exists := r.plugins[name]; exists {
		return errors.New(errors.ErrPlugin, fmt.Sprintf("plugin %s already registered", name), nil)
	}

	r.plugins[name] = plugin
	return nil
}

// GetPlugin retrieves a plugin by name
func (r *pluginRegistry) GetPlugin(name string) (types.Plugin, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	plugin, exists := r.plugins[name]
	if !exists {
		return nil, errors.New(errors.ErrPlugin, fmt.Sprintf("plugin %s not found", name), nil)
	}

	return plugin, nil
}

// ListPlugins returns all registered plugins
func (r *pluginRegistry) ListPlugins() []types.Plugin {
	r.mu.RLock()
	defer r.mu.RUnlock()

	plugins := make([]types.Plugin, 0, len(r.plugins))
	for _, plugin := range r.plugins {
		plugins = append(plugins, plugin)
	}

	return plugins
}

// UnregisterPlugin removes a plugin from the registry
func (r *pluginRegistry) UnregisterPlugin(name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.plugins[name]; !exists {
		return errors.New(errors.ErrPlugin, fmt.Sprintf("plugin %s not found", name), nil)
	}

	delete(r.plugins, name)
	return nil
}

// GetPluginStatus returns the status of a specific plugin
func (r *pluginRegistry) GetPluginStatus(name string) (*types.PluginStatus, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	plugin, exists := r.plugins[name]
	if !exists {
		return nil, errors.New(errors.ErrPlugin, fmt.Sprintf("plugin %s not found", name), nil)
	}

	return plugin.GetStatus(), nil
}
