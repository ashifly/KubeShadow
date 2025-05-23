package registry

import (
	"kubeshadow/pkg/types"
	"sync"
)

var (
	modules = make(map[string]types.Module)
	mu      sync.RWMutex
)

// Register registers a new module
func Register(module types.Module) {
	mu.Lock()
	defer mu.Unlock()
	modules[module.Name()] = module
}

// Get returns a module by name
func Get(name string) (types.Module, bool) {
	mu.RLock()
	defer mu.RUnlock()
	module, ok := modules[name]
	return module, ok
}

// List returns all registered modules
func List() []types.Module {
	mu.RLock()
	defer mu.RUnlock()
	result := make([]types.Module, 0, len(modules))
	for _, module := range modules {
		result = append(result, module)
	}
	return result
}
