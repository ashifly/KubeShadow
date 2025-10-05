package recon

import (
	"context"
	"fmt"
	"strings"

	"kubeshadow/pkg/logger"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// VulnerabilityInfo represents security vulnerabilities found in pods
type VulnerabilityInfo struct {
	PodName           string
	Namespace         string
	Severity          string
	VulnerabilityType string
	Description       string
	Recommendation    string
}

// PodVulnerabilityScan scans pods for security vulnerabilities
func PodVulnerabilityScan(ctx context.Context, kubeconfig string) ([]*VulnerabilityInfo, error) {
	var vulnerabilities []*VulnerabilityInfo

	// Create Kubernetes client
	config, err := getKubeConfig(kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("failed to get kubeconfig: %v", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create clientset: %v", err)
	}

	// Get all pods
	pods, err := clientset.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list pods: %v", err)
	}

	// Scan each pod for vulnerabilities
	for _, pod := range pods.Items {
		podVulns := scanPodForVulnerabilities(&pod)
		vulnerabilities = append(vulnerabilities, podVulns...)
	}

	return vulnerabilities, nil
}

// scanPodForVulnerabilities scans a single pod for security vulnerabilities
func scanPodForVulnerabilities(pod *v1.Pod) []*VulnerabilityInfo {
	var vulnerabilities []*VulnerabilityInfo

	// Check for runAsNonRoot: false
	if pod.Spec.SecurityContext != nil && pod.Spec.SecurityContext.RunAsNonRoot != nil && !*pod.Spec.SecurityContext.RunAsNonRoot {
		vulnerabilities = append(vulnerabilities, &VulnerabilityInfo{
			PodName:           pod.Name,
			Namespace:         pod.Namespace,
			Severity:          "HIGH",
			VulnerabilityType: "runAsNonRoot",
			Description:       "Pod is configured to run as root (runAsNonRoot: false)",
			Recommendation:    "Set runAsNonRoot: true and runAsUser to a non-root user",
		})
	}

	// Check for allowPrivilegeEscalation: true (this is at container level, not pod level)
	// We'll check this in the container loop below

	// Check for privileged containers and allowPrivilegeEscalation
	for _, container := range pod.Spec.Containers {
		if container.SecurityContext != nil && container.SecurityContext.Privileged != nil && *container.SecurityContext.Privileged {
			vulnerabilities = append(vulnerabilities, &VulnerabilityInfo{
				PodName:           pod.Name,
				Namespace:         pod.Namespace,
				Severity:          "CRITICAL",
				VulnerabilityType: "privileged",
				Description:       fmt.Sprintf("Container '%s' is running in privileged mode", container.Name),
				Recommendation:    "Remove privileged: true from container security context",
			})
		}

		// Check for allowPrivilegeEscalation: true
		if container.SecurityContext != nil && container.SecurityContext.AllowPrivilegeEscalation != nil && *container.SecurityContext.AllowPrivilegeEscalation {
			vulnerabilities = append(vulnerabilities, &VulnerabilityInfo{
				PodName:           pod.Name,
				Namespace:         pod.Namespace,
				Severity:          "HIGH",
				VulnerabilityType: "allowPrivilegeEscalation",
				Description:       fmt.Sprintf("Container '%s' allows privilege escalation", container.Name),
				Recommendation:    "Set allowPrivilegeEscalation: false",
			})
		}
	}

	// Check for hostNetwork: true
	if pod.Spec.HostNetwork {
		vulnerabilities = append(vulnerabilities, &VulnerabilityInfo{
			PodName:           pod.Name,
			Namespace:         pod.Namespace,
			Severity:          "HIGH",
			VulnerabilityType: "hostNetwork",
			Description:       "Pod is using host network (hostNetwork: true)",
			Recommendation:    "Remove hostNetwork: true and use ClusterIP or NodePort services",
		})
	}

	// Check for hostPID: true
	if pod.Spec.HostPID {
		vulnerabilities = append(vulnerabilities, &VulnerabilityInfo{
			PodName:           pod.Name,
			Namespace:         pod.Namespace,
			Severity:          "HIGH",
			VulnerabilityType: "hostPID",
			Description:       "Pod is using host PID namespace (hostPID: true)",
			Recommendation:    "Remove hostPID: true to isolate container processes",
		})
	}

	// Check for hostIPC: true
	if pod.Spec.HostIPC {
		vulnerabilities = append(vulnerabilities, &VulnerabilityInfo{
			PodName:           pod.Name,
			Namespace:         pod.Namespace,
			Severity:          "HIGH",
			VulnerabilityType: "hostIPC",
			Description:       "Pod is using host IPC namespace (hostIPC: true)",
			Recommendation:    "Remove hostIPC: true to isolate container IPC",
		})
	}

	// Check for dangerous hostPath mounts
	for _, volume := range pod.Spec.Volumes {
		if volume.HostPath != nil {
			path := volume.HostPath.Path
			if isDangerousHostPath(path) {
				vulnerabilities = append(vulnerabilities, &VulnerabilityInfo{
					PodName:           pod.Name,
					Namespace:         pod.Namespace,
					Severity:          "CRITICAL",
					VulnerabilityType: "hostPath",
					Description:       fmt.Sprintf("Pod has dangerous hostPath mount: %s", path),
					Recommendation:    "Remove hostPath mounts or use readOnly: true",
				})
			}
		}
	}

	// Check for automountServiceAccountToken: true
	if pod.Spec.AutomountServiceAccountToken != nil && *pod.Spec.AutomountServiceAccountToken {
		vulnerabilities = append(vulnerabilities, &VulnerabilityInfo{
			PodName:           pod.Name,
			Namespace:         pod.Namespace,
			Severity:          "MEDIUM",
			VulnerabilityType: "automountServiceAccountToken",
			Description:       "Pod automatically mounts service account token (automountServiceAccountToken: true)",
			Recommendation:    "Set automountServiceAccountToken: false if not needed",
		})
	}

	// Check for privileged init containers
	for _, initContainer := range pod.Spec.InitContainers {
		if initContainer.SecurityContext != nil && initContainer.SecurityContext.Privileged != nil && *initContainer.SecurityContext.Privileged {
			vulnerabilities = append(vulnerabilities, &VulnerabilityInfo{
				PodName:           pod.Name,
				Namespace:         pod.Namespace,
				Severity:          "CRITICAL",
				VulnerabilityType: "privilegedInitContainer",
				Description:       fmt.Sprintf("Init container '%s' is running in privileged mode", initContainer.Name),
				Recommendation:    "Remove privileged: true from init container security context",
			})
		}

		// Check for init container running as root
		if initContainer.SecurityContext != nil && initContainer.SecurityContext.RunAsUser != nil && *initContainer.SecurityContext.RunAsUser == 0 {
			vulnerabilities = append(vulnerabilities, &VulnerabilityInfo{
				PodName:           pod.Name,
				Namespace:         pod.Namespace,
				Severity:          "HIGH",
				VulnerabilityType: "initContainerRoot",
				Description:       fmt.Sprintf("Init container '%s' is running as root (runAsUser: 0)", initContainer.Name),
				Recommendation:    "Set runAsUser to a non-root user for init container",
			})
		}
	}

	// Check for excessive capabilities
	for _, container := range pod.Spec.Containers {
		if container.SecurityContext != nil && container.SecurityContext.Capabilities != nil {
			for _, cap := range container.SecurityContext.Capabilities.Add {
				if cap == "ALL" {
					vulnerabilities = append(vulnerabilities, &VulnerabilityInfo{
						PodName:           pod.Name,
						Namespace:         pod.Namespace,
						Severity:          "HIGH",
						VulnerabilityType: "excessiveCapabilities",
						Description:       fmt.Sprintf("Container '%s' has ALL capabilities", container.Name),
						Recommendation:    "Remove ALL capability and add only necessary capabilities",
					})
				}
			}
		}
	}

	// Check for readOnlyRootFilesystem: false
	for _, container := range pod.Spec.Containers {
		if container.SecurityContext != nil && container.SecurityContext.ReadOnlyRootFilesystem != nil && !*container.SecurityContext.ReadOnlyRootFilesystem {
			vulnerabilities = append(vulnerabilities, &VulnerabilityInfo{
				PodName:           pod.Name,
				Namespace:         pod.Namespace,
				Severity:          "MEDIUM",
				VulnerabilityType: "readOnlyRootFilesystem",
				Description:       fmt.Sprintf("Container '%s' has writable root filesystem", container.Name),
				Recommendation:    "Set readOnlyRootFilesystem: true and use emptyDir volumes for writable data",
			})
		}
	}

	return vulnerabilities
}

// isDangerousHostPath checks if a hostPath is dangerous
func isDangerousHostPath(path string) bool {
	dangerousPaths := []string{
		"/etc",
		"/root",
		"/var/run",
		"/proc",
		"/sys",
		"/dev",
		"/var/lib",
		"/opt",
		"/tmp",
		"/home",
		"/usr",
		"/bin",
		"/sbin",
		"/lib",
		"/lib64",
		"/var/log",
		"/etc/kubernetes",
		"/var/lib/kubelet",
		"/etc/docker",
		"/var/lib/docker",
		"/etc/systemd",
		"/var/lib/systemd",
	}

	for _, dangerousPath := range dangerousPaths {
		if strings.HasPrefix(path, dangerousPath) {
			return true
		}
	}

	return false
}

// getKubeConfig creates a Kubernetes config
func getKubeConfig(kubeconfig string) (*rest.Config, error) {
	if kubeconfig != "" {
		return clientcmd.BuildConfigFromFlags("", kubeconfig)
	}
	return rest.InClusterConfig()
}

// PrintVulnerabilities prints vulnerabilities in a formatted way
func PrintVulnerabilities(vulnerabilities []*VulnerabilityInfo) {
	if len(vulnerabilities) == 0 {
		logger.Info("✅ No security vulnerabilities found in pods")
		return
	}

	logger.Info("🚨 Found %d security vulnerabilities:", len(vulnerabilities))
	logger.Info("")

	// Group by severity
	critical := []*VulnerabilityInfo{}
	high := []*VulnerabilityInfo{}
	medium := []*VulnerabilityInfo{}
	low := []*VulnerabilityInfo{}

	for _, vuln := range vulnerabilities {
		switch vuln.Severity {
		case "CRITICAL":
			critical = append(critical, vuln)
		case "HIGH":
			high = append(high, vuln)
		case "MEDIUM":
			medium = append(medium, vuln)
		case "LOW":
			low = append(low, vuln)
		}
	}

	// Print critical vulnerabilities
	if len(critical) > 0 {
		logger.Info("🔴 CRITICAL VULNERABILITIES (%d):", len(critical))
		for _, vuln := range critical {
			logger.Info("  • %s/%s - %s: %s", vuln.Namespace, vuln.PodName, vuln.VulnerabilityType, vuln.Description)
			logger.Info("    Recommendation: %s", vuln.Recommendation)
			logger.Info("")
		}
	}

	// Print high vulnerabilities
	if len(high) > 0 {
		logger.Info("🟠 HIGH VULNERABILITIES (%d):", len(high))
		for _, vuln := range high {
			logger.Info("  • %s/%s - %s: %s", vuln.Namespace, vuln.PodName, vuln.VulnerabilityType, vuln.Description)
			logger.Info("    Recommendation: %s", vuln.Recommendation)
			logger.Info("")
		}
	}

	// Print medium vulnerabilities
	if len(medium) > 0 {
		logger.Info("🟡 MEDIUM VULNERABILITIES (%d):", len(medium))
		for _, vuln := range medium {
			logger.Info("  • %s/%s - %s: %s", vuln.Namespace, vuln.PodName, vuln.VulnerabilityType, vuln.Description)
			logger.Info("    Recommendation: %s", vuln.Recommendation)
			logger.Info("")
		}
	}

	// Print low vulnerabilities
	if len(low) > 0 {
		logger.Info("🟢 LOW VULNERABILITIES (%d):", len(low))
		for _, vuln := range low {
			logger.Info("  • %s/%s - %s: %s", vuln.Namespace, vuln.PodName, vuln.VulnerabilityType, vuln.Description)
			logger.Info("    Recommendation: %s", vuln.Recommendation)
			logger.Info("")
		}
	}

	// Print summary
	logger.Info("📊 VULNERABILITY SUMMARY:")
	logger.Info("  🔴 Critical: %d", len(critical))
	logger.Info("  🟠 High: %d", len(high))
	logger.Info("  🟡 Medium: %d", len(medium))
	logger.Info("  🟢 Low: %d", len(low))
	logger.Info("  📈 Total: %d", len(vulnerabilities))
}
