package metrics

import (
	"context"
	"kubeshadow/pkg/types"
	"sync"
)

// MetricsPlugin implements the Plugin interface for collecting metrics
type MetricsPlugin struct {
	name    string
	version string
	status  string
	mu      sync.RWMutex
	metrics map[string]float64
}

// NewMetricsPlugin creates a new metrics plugin
func NewMetricsPlugin() *MetricsPlugin {
	return &MetricsPlugin{
		name:    "metrics",
		version: "1.0.0",
		status:  "initialized",
		metrics: make(map[string]float64),
	}
}

// Name returns the plugin name
func (p *MetricsPlugin) Name() string {
	return p.name
}

// Version returns the plugin version
func (p *MetricsPlugin) Version() string {
	return p.version
}

// Initialize initializes the metrics plugin
func (p *MetricsPlugin) Initialize(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.status = "running"
	return nil
}

// Execute runs the metrics collection
func (p *MetricsPlugin) Execute(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Simulate metrics collection
	p.metrics["cpu_usage"] = 45.5
	p.metrics["memory_usage"] = 60.2
	p.metrics["pod_count"] = 10.0

	return nil
}

// Cleanup cleans up the metrics plugin
func (p *MetricsPlugin) Cleanup(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.status = "stopped"
	p.metrics = make(map[string]float64)
	return nil
}

// GetStatus returns the current status of the plugin
func (p *MetricsPlugin) GetStatus() *types.PluginStatus {
	p.mu.RLock()
	defer p.mu.RUnlock()

	return &types.PluginStatus{
		Name:    p.name,
		Version: p.version,
		Status:  p.status,
	}
}

// GetMetrics returns the current metrics
func (p *MetricsPlugin) GetMetrics() map[string]float64 {
	p.mu.RLock()
	defer p.mu.RUnlock()

	metrics := make(map[string]float64)
	for k, v := range p.metrics {
		metrics[k] = v
	}
	return metrics
}
