package dashboard

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
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

	// Simple approach: just run the command and capture any error
	// Output will still go to stdout normally
	var err error
	if originalRunE != nil {
		err = originalRunE(cmd, args)
	} else {
		err = w.runCommandDirectly(cmd, args)
	}

	endTime := time.Now()

	// Create a proper CommandResult for the dashboard
	result := CommandResult{
		ID:        generateID(),
		Command:   cmd.Name(),
		Module:    w.module,
		Arguments: args,
		Flags:     make(map[string]interface{}),
		Status:    "completed",
		StartTime: startTime,
		EndTime:   &endTime,
		Duration:  endTime.Sub(startTime),
		Output:    fmt.Sprintf("Command executed: %s", cmd.Name()),
		ExitCode:  0,
		Metadata:  make(map[string]interface{}),
	}

	if err != nil {
		result.Status = "error"
		result.ErrorMsg = err.Error()
		result.ExitCode = 1
	}

	// Debug output (can be removed later)
	fmt.Printf("✅ Published %s command to dashboard\n", result.Command)

	// Try to publish to HTTP endpoint first (for existing dashboard instances)
	if publishedViaHTTP := publishResultViaHTTP(result, 8080); publishedViaHTTP {
		return err
	}

	// Fallback to local singleton instance
	GetInstance().PublishResult(result)

	return err
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
