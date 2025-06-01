package sidecar

import (
	"context"
	"kubeshadow/pkg/testutil"
	"testing"
)

func TestSidecarModule(t *testing.T) {
	module := NewSidecarModule()
	if module == nil {
		t.Fatal("Failed to create sidecar module")
	}

	// Test command setup
	cmd := module.Command()
	if cmd == nil {
		t.Fatal("Command is nil")
	}

	// Test flag setting
	if err := cmd.Flags().Set("mode", "api"); err != nil {
		t.Fatalf("Failed to set mode flag: %v", err)
	}
	if err := cmd.Flags().Set("pod", "test-pod"); err != nil {
		t.Fatalf("Failed to set pod flag: %v", err)
	}
	if err := cmd.Flags().Set("namespace", "default"); err != nil {
		t.Fatalf("Failed to set namespace flag: %v", err)
	}

	// Test execution
	if err := module.Execute(context.Background()); err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	// Test status
	status := module.GetStatus()
	if status != "ready" {
		t.Errorf("Expected status 'ready', got '%s'", status)
	}
}

func TestSidecarModule_Integration(t *testing.T) {
	// Skip if not running integration tests
	if testing.Short() {
		t.Skip("Skipping integration test")
	}

	ctx := testutil.TestContext(t)
	module := NewSidecarModule()

	// Test API mode
	t.Run("API Mode", func(t *testing.T) {
		module.Command().Flags().Set("mode", "api")
		module.Command().Flags().Set("pod", "test-pod")
		module.Command().Flags().Set("namespace", "default")
		module.Command().Flags().Set("config", testutil.CreateTempConfig(t, `{"image": "test-image:latest"}`))

		if err := module.Validate(); err != nil {
			t.Errorf("Validate() error = %v", err)
		}

		if err := module.Execute(ctx); err != nil {
			t.Errorf("Execute() error = %v", err)
		}

		status := module.GetStatus()
		if status != "stopped" {
			t.Errorf("Expected status 'stopped', got %s", status)
		}
	})

	// Test etcd mode
	t.Run("Etcd Mode", func(t *testing.T) {
		module.Command().Flags().Set("mode", "etcd")
		module.Command().Flags().Set("pod", "test-pod")
		module.Command().Flags().Set("namespace", "default")
		module.Command().Flags().Set("config", testutil.CreateTempConfig(t, `{"image": "test-image:latest"}`))

		if err := module.Validate(); err != nil {
			t.Errorf("Validate() error = %v", err)
		}

		if err := module.Execute(ctx); err != nil {
			t.Errorf("Execute() error = %v", err)
		}

		status := module.GetStatus()
		if status != "stopped" {
			t.Errorf("Expected status 'stopped', got %s", status)
		}
	})

	// Test cleanup
	t.Run("Cleanup", func(t *testing.T) {
		if err := module.Cleanup(); err != nil {
			t.Errorf("Cleanup() error = %v", err)
		}
	})
}
