package dashboard

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/google/uuid"
)

// Publisher provides functionality to publish command results to the dashboard
type Publisher struct {
	dashboard *Dashboard
	result    *CommandResult
}

// NewPublisher creates a new publisher for a command
func NewPublisher(module, command string, args []string, flags map[string]interface{}) *Publisher {
	result := &CommandResult{
		ID:        uuid.New().String(),
		Command:   command,
		Module:    module,
		Arguments: args,
		Flags:     flags,
		Status:    "running",
		StartTime: time.Now(),
		Metadata:  make(map[string]interface{}),
	}

	return &Publisher{
		dashboard: GetInstance(),
		result:    result,
	}
}

// Start marks the command as started and publishes initial result
func (p *Publisher) Start() {
	if !p.dashboard.IsEnabled() {
		return
	}

	p.result.Status = "running"
	p.result.StartTime = time.Now()
	p.dashboard.PublishResult(*p.result)
}

// Complete marks the command as completed and publishes final result
func (p *Publisher) Complete(output string, exitCode int) {
	if !p.dashboard.IsEnabled() {
		return
	}

	endTime := time.Now()
	p.result.Status = "completed"
	p.result.EndTime = &endTime
	p.result.Duration = endTime.Sub(p.result.StartTime)
	p.result.Output = output
	p.result.ExitCode = exitCode
	p.dashboard.PublishResult(*p.result)
}

// Error marks the command as failed and publishes error result
func (p *Publisher) Error(errorMsg string, output string, exitCode int) {
	if !p.dashboard.IsEnabled() {
		return
	}

	endTime := time.Now()
	p.result.Status = "error"
	p.result.EndTime = &endTime
	p.result.Duration = endTime.Sub(p.result.StartTime)
	p.result.ErrorMsg = errorMsg
	p.result.Output = output
	p.result.ExitCode = exitCode
	p.dashboard.PublishResult(*p.result)
}

// UpdateOutput updates the command output (useful for streaming output)
func (p *Publisher) UpdateOutput(output string) {
	if !p.dashboard.IsEnabled() {
		return
	}

	p.result.Output = output
	p.dashboard.PublishResult(*p.result)
}

// SetMetadata sets metadata for the command result
func (p *Publisher) SetMetadata(key string, value interface{}) {
	if !p.dashboard.IsEnabled() {
		return
	}

	p.result.Metadata[key] = value
	p.dashboard.PublishResult(*p.result)
}

// GetID returns the unique ID of this command execution
func (p *Publisher) GetID() string {
	return p.result.ID
}

// CaptureWriter creates a writer that captures output for the dashboard
type CaptureWriter struct {
	original  io.Writer
	buffer    *bytes.Buffer
	publisher *Publisher
}

// NewCaptureWriter creates a new capture writer
func NewCaptureWriter(original io.Writer, publisher *Publisher) *CaptureWriter {
	return &CaptureWriter{
		original:  original,
		buffer:    &bytes.Buffer{},
		publisher: publisher,
	}
}

// Write implements io.Writer interface
func (cw *CaptureWriter) Write(p []byte) (n int, err error) {
	// Write to original writer (stdout/stderr)
	n, err = cw.original.Write(p)
	if err != nil {
		return n, err
	}

	// Also capture to buffer
	cw.buffer.Write(p)

	// Update dashboard with current output
	if cw.publisher != nil {
		cw.publisher.UpdateOutput(cw.buffer.String())
	}

	return n, nil
}

// GetOutput returns the captured output
func (cw *CaptureWriter) GetOutput() string {
	return cw.buffer.String()
}

// WrapStdout wraps stdout to capture output for dashboard publishing
func WrapStdout(publisher *Publisher) (*CaptureWriter, func()) {
	if !GetInstance().IsEnabled() || publisher == nil {
		return nil, func() {}
	}

	originalStdout := os.Stdout
	captureWriter := NewCaptureWriter(originalStdout, publisher)

	// Create a pipe to capture stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	// Start goroutine to copy from pipe to both original stdout and capture buffer
	go func() {
		buffer := make([]byte, 1024)
		for {
			n, err := r.Read(buffer)
			if err != nil {
				break
			}
			captureWriter.Write(buffer[:n])
		}
	}()

	// Return restore function
	restore := func() {
		w.Close()
		os.Stdout = originalStdout
	}

	return captureWriter, restore
}

// CreateCommandPublisher is a helper function to create a publisher from cobra command context
func CreateCommandPublisher(module string, cmdName string, args []string, flagValues map[string]interface{}) *Publisher {
	return NewPublisher(module, cmdName, args, flagValues)
}

// StartDashboardIfRequested starts the dashboard if the dashboard flag is enabled
func StartDashboardIfRequested(dashboardFlag bool, port int) error {
	if !dashboardFlag {
		return nil
	}

	dashboard := GetInstance()
	if dashboard.IsEnabled() {
		fmt.Printf("📊 Dashboard already running on http://localhost:%d\n", port)
		return nil
	}

	// Check if a KubeShadow dashboard is already running on this port
	if isDashboardRunningOnPort(port) {
		fmt.Printf("📊 Using existing dashboard on http://localhost:%d\n", port)
		return nil
	}

	return dashboard.Start(port)
}

// isDashboardRunningOnPort checks if a KubeShadow dashboard is already running on the specified port
func isDashboardRunningOnPort(port int) bool {
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(fmt.Sprintf("http://localhost:%d/api/stats", port))
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	// If we get a successful response, assume it's our dashboard
	return resp.StatusCode == http.StatusOK
}
