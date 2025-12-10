package dashboard

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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
		// Check if dashboard is explicitly enabled via flag
		dashboardEnabled := false
		if localFlag, err := cmd.Flags().GetBool("dashboard"); err == nil {
			dashboardEnabled = localFlag
		}
		if !dashboardEnabled {
			if persistentFlag, err := cmd.Root().PersistentFlags().GetBool("dashboard"); err == nil {
				dashboardEnabled = persistentFlag
			}
		}

		// If not explicitly enabled, auto-detect if dashboard is running
		if !dashboardEnabled {
			// Check if dashboard is already running (auto-detect)
			dashboardPort := 8080 // Default port
			if portFlag, err := cmd.Root().PersistentFlags().GetInt("dashboard-port"); err == nil && portFlag > 0 {
				dashboardPort = portFlag
			}
			
			// Check if dashboard instance is enabled or if one is running on the port
			dashboardInstance := GetInstance()
			if dashboardInstance.IsEnabled() || isDashboardRunningOnPort(dashboardPort) {
				dashboardEnabled = true
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
	// Create publisher for this command execution
	flags := extractFlags(cmd)
	publisher := NewPublisher(w.module, cmd.Name(), args, flags)
	publisher.Start()

	// Note: We can't directly replace os.Stdout/Stderr since they are *os.File types
	// Instead, we'll use a simpler approach: capture output via the publisher
	// Modules can publish detailed results themselves using the Publisher API
	// For now, we'll publish basic command execution info
	
	// Run the command (output will go to original stdout/stderr)
	var err error
	if originalRunE != nil {
		err = originalRunE(cmd, args)
	} else {
		err = w.runCommandDirectly(cmd, args)
	}

	// Note: Since we can't easily replace os.Stdout/Stderr with our wrapper,
	// we'll capture output by using the publisher's UpdateOutput mechanism
	// For now, we'll publish a basic result and let modules publish detailed results themselves
	
	// Provide a basic message - modules should publish detailed results themselves
	fullOutput := fmt.Sprintf("Command '%s' executed", cmd.Name())
	if len(args) > 0 {
		fullOutput += fmt.Sprintf(" with args: %v", args)
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
