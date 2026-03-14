package metrics

import (
	"context"
	"testing"
	"time"
)

func TestMetricsPlugin(t *testing.T) {
	plugin := NewMetricsPlugin()
	ctx := context.Background()

	t.Run("Initialization", func(t *testing.T) {
		if plugin.Name() != "metrics" {
			t.Errorf("Name() = %v, want %v", plugin.Name(), "metrics")
		}
		if plugin.Version() != "1.0.0" {
			t.Errorf("Version() = %v, want %v", plugin.Version(), "1.0.0")
		}
		status := plugin.GetStatus()
		if status.Status != "initialized" {
			t.Errorf("GetStatus().Status = %v, want %v", status.Status, "initialized")
		}
	})

	t.Run("Lifecycle", func(t *testing.T) {
		// Test initialization
		if err := plugin.Initialize(ctx); err != nil {
			t.Errorf("Initialize() error = %v", err)
		}
		if status := plugin.GetStatus(); status.Status != "running" {
			t.Errorf("Status after Initialize() = %v, want %v", status.Status, "running")
		}

		// Test execution
		if err := plugin.Execute(ctx); err != nil {
			t.Errorf("Execute() error = %v", err)
		}
		metrics := plugin.GetMetrics()
		if len(metrics) != 3 {
			t.Errorf("GetMetrics() returned %d metrics, want 3", len(metrics))
		}

		// Test cleanup
		if err := plugin.Cleanup(ctx); err != nil {
			t.Errorf("Cleanup() error = %v", err)
		}
		if status := plugin.GetStatus(); status.Status != "stopped" {
			t.Errorf("Status after Cleanup() = %v, want %v", status.Status, "stopped")
		}
		if len(plugin.GetMetrics()) != 0 {
			t.Error("Metrics not cleared after cleanup")
		}
	})

	t.Run("ConcurrentAccess", func(t *testing.T) {
		// Test concurrent access to metrics
		done := make(chan bool)
		for i := 0; i < 10; i++ {
			go func() {
				plugin.Execute(ctx)
				plugin.GetMetrics()
				done <- true
			}()
		}

		// Wait for all goroutines to complete
		for i := 0; i < 10; i++ {
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Error("Timeout waiting for concurrent operations")
			}
		}
	})
}
