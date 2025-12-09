package dashboard

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// ModuleWrapper wraps any command to automatically publish results to dashboard
type ModuleWrapper struct {
	module  string
	command *cobra.Command
}

// WrapCommand wraps a cobra command to automatically publish results
func WrapCommand(module string, cmd *cobra.Command) *cobra.Command {
	wrapper := &ModuleWrapper{
		module:  module,
		command: cmd,
	}

	// Store original RunE
	originalRunE := cmd.RunE

	// Wrap with dashboard integration
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		// Check if dashboard is enabled (check both local and persistent flags)
		dashboardEnabled := false
		if localFlag, err := cmd.Flags().GetBool("dashboard"); err == nil {
			dashboardEnabled = localFlag
		}
		if !dashboardEnabled {
			if persistentFlag, err := cmd.Root().PersistentFlags().GetBool("dashboard"); err == nil {
				dashboardEnabled = persistentFlag
			}
		}

		if !dashboardEnabled {
			// Run original command without dashboard
			if originalRunE != nil {
				return originalRunE(cmd, args)
			}
			return nil
		}

		// Run with dashboard integration
		return wrapper.runWithDashboard(cmd, args, originalRunE)
	}

	return cmd
}

// runWithDashboard runs the command and publishes results to dashboard
func (w *ModuleWrapper) runWithDashboard(cmd *cobra.Command, args []string, originalRunE func(*cobra.Command, []string) error) error {
	startTime := time.Now()
	
	// Create publisher for this command execution
	flags := extractFlags(cmd)
	publisher := NewPublisher(w.module, cmd.Name(), args, flags)
	publisher.Start()

	// Capture stdout/stderr to get full output while still showing on CLI
	var outputBuffer bytes.Buffer
	var errorBuffer bytes.Buffer
	
	// Save original stdout/stderr
	originalStdout := os.Stdout
	originalStderr := os.Stderr
	
	// Create multi-writer: write to both original (CLI) and buffer (dashboard)
	multiStdout := io.MultiWriter(originalStdout, &outputBuffer)
	multiStderr := io.MultiWriter(originalStderr, &errorBuffer)
	
	// Wrap with writer that updates dashboard in real-time
	stdoutWrapper := &writerWrapper{
		Writer:    multiStdout,
		buffer:    &outputBuffer,
		publisher: publisher,
	}
	stderrWrapper := &writerWrapper{
		Writer:    multiStderr,
		buffer:    &errorBuffer,
		publisher: publisher,
	}
	
	// Temporarily replace stdout/stderr
	os.Stdout = stdoutWrapper
	os.Stderr = stderrWrapper
	
	// Restore on exit
	defer func() {
		os.Stdout = originalStdout
		os.Stderr = originalStderr
	}()

	// Run the command
	var err error
	if originalRunE != nil {
		err = originalRunE(cmd, args)
	} else {
		err = w.runCommandDirectly(cmd, args)
	}

	// Collect final captured output
	fullOutput := outputBuffer.String()
	if errorBuffer.Len() > 0 {
		fullOutput += "\n--- STDERR ---\n" + errorBuffer.String()
	}

	// Complete the publisher with full output
	if err != nil {
		publisher.Error(err.Error(), fullOutput, 1)
	} else {
		publisher.Complete(fullOutput, 0)
	}

	return err
}

// writerWrapper wraps a writer to update dashboard in real-time
type writerWrapper struct {
	io.Writer
	buffer    *bytes.Buffer
	publisher *Publisher
}

func (w *writerWrapper) Write(p []byte) (n int, err error) {
	n, err = w.Writer.Write(p) // Write to both CLI and buffer
	if err == nil && w.publisher != nil {
		// Update dashboard with current output in real-time
		w.publisher.UpdateOutput(w.buffer.String())
	}
	return n, err
}

// extractFlags extracts flag values from a cobra command
func extractFlags(cmd *cobra.Command) map[string]interface{} {
	flags := make(map[string]interface{})
	cmd.Flags().VisitAll(func(flag *pflag.Flag) {
		if flag.Changed {
			switch flag.Value.Type() {
			case "bool":
				if val, err := cmd.Flags().GetBool(flag.Name); err == nil {
					flags[flag.Name] = val
				}
			case "string":
				if val, err := cmd.Flags().GetString(flag.Name); err == nil {
					flags[flag.Name] = val
				}
			case "int":
				if val, err := cmd.Flags().GetInt(flag.Name); err == nil {
					flags[flag.Name] = val
				}
			default:
				flags[flag.Name] = flag.Value.String()
			}
		}
	})
	return flags
}

// runCommandDirectly runs a command without RunE
func (w *ModuleWrapper) runCommandDirectly(cmd *cobra.Command, _ []string) error {
	// This is a fallback for commands without RunE
	// In practice, most commands should have RunE
	return fmt.Errorf("command %s has no RunE function", cmd.Name())
}

// EnableDashboardForModule enables dashboard integration for a specific module
func EnableDashboardForModule(module string, cmd *cobra.Command) {
	// Don't add dashboard flag if it already exists (it's a persistent flag)
	if cmd.Flags().Lookup("dashboard") == nil &&
		(cmd.Root() == nil || cmd.Root().PersistentFlags().Lookup("dashboard") == nil) {
		cmd.Flags().Bool("dashboard", false, "Enable dashboard to display results")
	}

	// Wrap the command
	WrapCommand(module, cmd)
}

// generateID generates a unique ID for command results
func generateID() string {
	return uuid.New().String()
}

// publishResultViaHTTP publishes a result to an existing dashboard via HTTP
func publishResultViaHTTP(result CommandResult, port int) bool {
	data, err := json.Marshal(result)
	if err != nil {
		return false
	}

	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Post(
		fmt.Sprintf("http://localhost:%d/api/publish", port),
		"application/json",
		bytes.NewBuffer(data),
	)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode == http.StatusOK
}

// AutoPublishResult automatically publishes a result to the dashboard
func AutoPublishResult(module, command string, result interface{}, output string, err error) {
	PublishModuleResult(module, command, result, output, err)
}

// GetDashboardURL returns the current dashboard URL
func GetDashboardURL() string {
	if !GetInstance().enabled {
		return ""
	}

	// Get the actual port being used
	// This would need to be tracked in the Dashboard struct
	return "http://localhost:8080" // Default, should be made dynamic
}
