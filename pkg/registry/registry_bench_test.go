package registry

import (
	"kubeshadow/pkg/modules/sidecar"
	"testing"
)

func BenchmarkRegisterModule(b *testing.B) {
	registry := NewModuleRegistry()
	module := sidecar.NewSidecarModule()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		registry.RegisterModule(module)
	}
}

func BenchmarkGetModule(b *testing.B) {
	registry := NewModuleRegistry()
	module := sidecar.NewSidecarModule()
	registry.RegisterModule(module)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		registry.GetModule("sidecar")
	}
}

func BenchmarkListModules(b *testing.B) {
	registry := NewModuleRegistry()
	module := sidecar.NewSidecarModule()
	registry.RegisterModule(module)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		registry.ListModules()
	}
}

func BenchmarkGetModuleStatus(b *testing.B) {
	registry := NewModuleRegistry()
	module := sidecar.NewSidecarModule()
	registry.RegisterModule(module)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		registry.GetModuleStatus("sidecar")
	}
}
