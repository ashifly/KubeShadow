package stealth

import (
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
	// CleanupCmd represents the command for cleanup operations
	CleanupCmd = &cobra.Command{
		Use:   "cleanup",
		Short: "Clean up artifacts from penetration testing activities",
		Long:  `Provides utilities to remove injected pods, wipe container logs, delete service accounts, or perform other cleanup tasks after testing.`, // Added Long description
		RunE: func(cmd *cobra.Command, args []string) error {
			// Get flags to determine cleanup action
			cleanupPod, _ := cmd.Flags().GetBool("pod")
			cleanupLogs, _ := cmd.Flags().GetBool("logs")
			cleanupSA, _ := cmd.Flags().GetBool("serviceaccount")

			// Get target details from flags
			name, _ := cmd.Flags().GetString("name")
			namespace, _ := cmd.Flags().GetString("namespace")
			node, _ := cmd.Flags().GetString("node")
			containerID, _ := cmd.Flags().GetString("container-id")

			// Validate that at least one cleanup action is specified
			if !cleanupPod && !cleanupLogs && !cleanupSA {
				return errors.New(errors.ErrValidation, "at least one cleanup action flag (--pod, --logs, --serviceaccount) must be specified", nil)
			}

			// Perform cleanup based on flags
			var cleanupErrors []error

			if cleanupPod {
				if name == "" || namespace == "" {
					cleanupErrors = append(cleanupErrors, errors.New(errors.ErrValidation, "--name and --namespace are required for pod cleanup", nil))
				} else {
					if err := RemoveInjectedPods(name, namespace); err != nil {
						cleanupErrors = append(cleanupErrors, err)
					}
				}
			}

			if cleanupLogs {
				if node == "" || containerID == "" {
					cleanupErrors = append(cleanupErrors, errors.New(errors.ErrValidation, "--node and --container-id are required for log cleanup", nil))
				} else {
					// Note: WipeContainerLogs currently uses ssh, which requires setup outside the tool.
					// A more integrated approach might involve a DaemonSet or privileged container.
					logger.Warn("Wiping logs requires SSH access to the node and appropriate permissions.")
					if err := WipeContainerLogs(node); err != nil {
						cleanupErrors = append(cleanupErrors, err)
					}
				}
			}

			if cleanupSA {
				if name == "" || namespace == "" {
					cleanupErrors = append(cleanupErrors, errors.New(errors.ErrValidation, "--name and --namespace are required for service account cleanup", nil))
				} else {
					if err := DeleteServiceAccount(name, namespace); err != nil {
						cleanupErrors = append(cleanupErrors, err)
					}
				}
			}

			// Report any errors encountered
			if len(cleanupErrors) > 0 {
				return errors.New(errors.ErrRuntime, "cleanup completed with errors", errors.NewMultiError(cleanupErrors))
			}

			logger.Info("Cleanup completed successfully.")
			return nil
		},
	}
)

func init() {
	// Define flags for cleanup actions
	CleanupCmd.Flags().Bool("pod", false, "Remove an injected pod")
	CleanupCmd.Flags().Bool("logs", false, "Attempt to wipe container logs on a node")
	CleanupCmd.Flags().Bool("serviceaccount", false, "Delete a created service account")

	// Define flags for target details
	CleanupCmd.Flags().String("name", "", "Name of the resource to clean up (pod or serviceaccount)")
	CleanupCmd.Flags().String("namespace", "", "Namespace of the resource to clean up")
	CleanupCmd.Flags().String("node", "", "Node name where the container is running (for log cleanup)")
	CleanupCmd.Flags().String("container-id", "", "Container ID whose logs to wipe (for log cleanup)")

	// Add flag dependencies or validation logic here if needed (e.g., require name/namespace with --pod)
}

// RemoveInjectedPods deletes a specified pod
func RemoveInjectedPods(podName, namespace string) error {
	logger.Info("Removing pod: %s in namespace: %s", podName, namespace)
	cmd := exec.Command("kubectl", "delete", "pod", podName, "-n", namespace, "--force", "--grace-period=0")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return errors.New(errors.ErrRuntime, fmt.Sprintf("error deleting pod %s/%s", namespace, podName), fmt.Errorf("%v\n%s", err, out))
	}
	logger.Info("Pod %s/%s removed.", namespace, podName)
	return nil
}

// WipeContainerLogs attempts to clean logs for a container on a node via SSH
func WipeContainerLogs(nodeName string) error {
	if !isValidNodeName(nodeName) {
		return fmt.Errorf("invalid node name: %s", nodeName)
	}

	logFilePath := filepath.Clean("/var/log/containers")
	if !strings.HasPrefix(logFilePath, "/var/log/") {
		return fmt.Errorf("invalid log path: %s", logFilePath)
	}

	cmd := exec.Command("truncate", "-s", "0", logFilePath)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to truncate logs: %v\nOutput: %s", err, output)
	}

	return nil
}

func CleanupAuditLogs() error {
	auditLogPath := "/var/log/audit/audit.log"
	if _, err := os.Stat(auditLogPath); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("audit log file does not exist: %s", auditLogPath)
		}
		return fmt.Errorf("failed to check audit log file: %v", err)
	}

	cmd := exec.Command("truncate", "-s", "0", auditLogPath)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to truncate audit logs: %v\nOutput: %s", err, output)
	}

	return nil
}

func RemoveSuspiciousFiles() error {
	suspiciousPaths := []string{
		"/tmp/backdoor",
		"/var/lib/kubelet/plugins/backdoor",
		"/etc/kubernetes/manifests/backdoor.yaml",
	}

	for _, path := range suspiciousPaths {
		if err := os.RemoveAll(path); err != nil {
			if !os.IsNotExist(err) {
				return fmt.Errorf("failed to remove suspicious file %s: %v", path, err)
			}
		}
	}

	return nil
}

func isValidNodeName(name string) bool {
	if len(name) == 0 || len(name) > 63 {
		return false
	}
	for _, c := range name {
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.') {
			return false
		}
	}
	return true
}

// DeleteServiceAccount deletes a specified service account
func DeleteServiceAccount(saName, namespace string) error {
	logger.Info("Deleting service account: %s in namespace: %s", saName, namespace)
	cmd := exec.Command("kubectl", "delete", "sa", saName, "-n", namespace)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return errors.New(errors.ErrRuntime, fmt.Sprintf("failed to delete service account %s/%s", namespace, saName), fmt.Errorf("%v\n%s", err, out))
	}
	logger.Info("Service account %s/%s deleted.", namespace, saName)
	return nil
}
