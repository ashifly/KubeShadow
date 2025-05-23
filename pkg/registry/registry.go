package registry

import (
	"fmt"
	"kubeshadow/pkg/errors"
	"kubeshadow/pkg/logger"
	"kubeshadow/pkg/types"
	"sync"
)

// ModuleRegistry manages the registration and lifecycle of modules
type ModuleRegistry struct {
	modules map[string]types.Module
	mu      sync.RWMutex
}

// NewModuleRegistry creates a new module registry
func NewModuleRegistry() *ModuleRegistry {
	return &ModuleRegistry{
		modules: make(map[string]types.Module),
	}
}

// RegisterModule registers a new module
func (r *ModuleRegistry) RegisterModule(module types.Module) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	name := module.Name()
	if _, exists := r.modules[name]; exists {
		return errors.New(errors.ErrModule, "module already registered", nil)
	}

	logger.Info("Registering module: %s", name)
	r.modules[name] = module
	return nil
}

// GetModule retrieves a module by name
func (r *ModuleRegistry) GetModule(name string) (types.Module, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	module, exists := r.modules[name]
	if !exists {
		return nil, errors.New(errors.ErrModule, "module not found", nil)
	}
	return module, nil
}

// ListModules returns a list of all registered module names
func (r *ModuleRegistry) ListModules() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	names := make([]string, 0, len(r.modules))
	for name := range r.modules {
		names = append(names, name)
	}
	return names
}

// GetModuleStatus returns the status of a module
func (r *ModuleRegistry) GetModuleStatus(name string) (*types.ModuleStatus, error) {
	module, err := r.GetModule(name)
	if err != nil {
		return nil, err
	}

	if baseModule, ok := module.(interface{ GetStatus() *types.ModuleStatus }); ok {
		return baseModule.GetStatus(), nil
	}

	return nil, fmt.Errorf("module does not support status tracking")
}

// GetAllModuleStatuses returns the status of all modules
func (r *ModuleRegistry) GetAllModuleStatuses() map[string]*types.ModuleStatus {
	r.mu.RLock()
	defer r.mu.RUnlock()

	statuses := make(map[string]*types.ModuleStatus)
	for name, module := range r.modules {
		if baseModule, ok := module.(interface{ GetStatus() *types.ModuleStatus }); ok {
			statuses[name] = baseModule.GetStatus()
		}
	}
	return statuses
}

// UnregisterModule removes a module from the registry
func (r *ModuleRegistry) UnregisterModule(name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.modules[name]; !exists {
		return errors.New(errors.ErrModule, "module not found", nil)
	}

	logger.Info("Unregistering module: %s", name)
	delete(r.modules, name)
	return nil
}
