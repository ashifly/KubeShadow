package dashboard

import (
	"fmt"
	"os"
	"strings"

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
		// Check if dashboard is enabled
		dashboardEnabled, _ := cmd.Flags().GetBool("dashboard")
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
	// Capture output
	var output strings.Builder
	var err error

	// Create a pipe to capture output
	reader, writer, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("failed to create pipe: %w", err)
	}
	defer reader.Close()
	defer writer.Close()

	// Redirect stdout to capture output
	originalStdout := os.Stdout
	os.Stdout = writer
	defer func() {
		os.Stdout = originalStdout
	}()

	// Run the original command
	if originalRunE != nil {
		err = originalRunE(cmd, args)
	} else {
		// If no RunE, try to run the command directly
		err = w.runCommandDirectly(cmd, args)
	}

	// Close the writer to signal end of output
	writer.Close()

	// Read all output from the pipe
	buf := make([]byte, 1024)
	for {
		n, err := reader.Read(buf)
		if n > 0 {
			output.Write(buf[:n])
		}
		if err != nil {
			break
		}
	}

	outputStr := output.String()

	// Publish result to dashboard
	PublishModuleResult(
		w.module,
		cmd.Name(),
		nil, // Result will be extracted from output
		outputStr,
		err,
	)

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
	// Add dashboard flag if not present
	if !cmd.Flags().Changed("dashboard") {
		cmd.Flags().Bool("dashboard", false, "Enable dashboard to display results")
	}

	// Wrap the command
	WrapCommand(module, cmd)
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
