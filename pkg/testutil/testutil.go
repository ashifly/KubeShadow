package testutil

import (
	"context"
	"kubeshadow/pkg/types"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestContext returns a context with timeout for tests
func TestContext(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(func() { cancel() })
	return ctx
}

// CreateTempFile creates a temporary file for testing
func CreateTempFile(t *testing.T, content string) *os.File {
	t.Helper()

	tmpfile, err := os.CreateTemp("", "kubeshadow-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}

	if err := os.WriteFile(tmpfile.Name(), []byte(content), 0600); err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}

	t.Cleanup(func() {
		if err := os.Remove(tmpfile.Name()); err != nil {
			t.Logf("Warning: failed to remove temp file: %v", err)
		}
	})

	return tmpfile
}

// CreateTempDir creates a temporary directory for testing
func CreateTempDir(t *testing.T) string {
	t.Helper()

	dir, err := os.MkdirTemp("", "kubeshadow-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}

	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Logf("Warning: failed to remove temp directory: %v", err)
		}
	})

	return dir
}

// WriteFile writes content to a file with secure permissions
func WriteFile(t *testing.T, path, content string) {
	t.Helper()

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0750); err != nil {
		t.Fatalf("Failed to create directory: %v", err)
	}

	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("Failed to write file: %v", err)
	}
}

// CreateTestModuleConfig creates a test module configuration
func CreateTestModuleConfig(enabled bool, config map[string]interface{}) *types.ModuleConfig {
	return &types.ModuleConfig{
		Enabled: enabled,
		Config:  config,
	}
}

// AssertModuleStatus checks if a module's status matches expected values
func AssertModuleStatus(t *testing.T, status *types.ModuleStatus, expectedStatus string, hasError bool) {
	t.Helper()
	if status.Status != expectedStatus {
		t.Errorf("Expected status %s, got %s", expectedStatus, status.Status)
	}
	if hasError && status.Error == "" {
		t.Error("Expected error, got none")
	}
	if !hasError && status.Error != "" {
		t.Errorf("Unexpected error: %s", status.Error)
	}
}

// SetupTestDir creates a temporary test directory
func SetupTestDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "kubeshadow-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

// CreateTestFile creates a test file in the given directory
func CreateTestFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}
	return path
}

// CreateTempConfig creates a temporary config file with the given content and returns its path
func CreateTempConfig(t *testing.T, content string) string {
	t.Helper()
	tmpfile, err := os.CreateTemp("", "kubeshadow-config-*.yaml")
	if err != nil {
		t.Fatalf("Failed to create temp config file: %v", err)
	}
	if err := os.WriteFile(tmpfile.Name(), []byte(content), 0600); err != nil {
		t.Fatalf("Failed to write to temp config file: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Remove(tmpfile.Name()); err != nil {
			t.Logf("Warning: failed to remove temp config file: %v", err)
		}
	})
	return tmpfile.Name()
}
