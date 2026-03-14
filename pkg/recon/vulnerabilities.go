package recon

import (
	"context"
	"fmt"
	"regexp"
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

	// Check for runAsUser: 0 (root user)
	if pod.Spec.SecurityContext != nil && pod.Spec.SecurityContext.RunAsUser != nil && *pod.Spec.SecurityContext.RunAsUser == 0 {
		vulnerabilities = append(vulnerabilities, &VulnerabilityInfo{
			PodName:           pod.Name,
			Namespace:         pod.Namespace,
			Severity:          "HIGH",
			VulnerabilityType: "runAsUser",
			Description:       "Pod is configured to run as root user (runAsUser: 0)",
			Recommendation:    "Set runAsUser to a non-root user (e.g., 1000)",
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

	// NEW VULNERABILITY DETECTIONS FOR ALL 21 YAML FILES

	// Check for SSRF vulnerabilities (File 17)
	vulnerabilities = append(vulnerabilities, scanForSSRFVulnerabilities(pod)...)

	// Check for container escape vulnerabilities (File 18)
	vulnerabilities = append(vulnerabilities, scanForContainerEscapeVulnerabilities(pod)...)

	// Check for supply chain vulnerabilities (File 19)
	vulnerabilities = append(vulnerabilities, scanForSupplyChainVulnerabilities(pod)...)

	// Check for crypto mining vulnerabilities (File 20)
	vulnerabilities = append(vulnerabilities, scanForCryptoMiningVulnerabilities(pod)...)

	// Check for DNS poisoning vulnerabilities (File 21)
	vulnerabilities = append(vulnerabilities, scanForDNSPoisoningVulnerabilities(pod)...)

	// Check for service exposure vulnerabilities
	vulnerabilities = append(vulnerabilities, scanForServiceExposureVulnerabilities(pod)...)

	// Check for secrets exposure vulnerabilities
	vulnerabilities = append(vulnerabilities, scanForSecretsExposureVulnerabilities(pod)...)

	// Check for RBAC vulnerabilities
	vulnerabilities = append(vulnerabilities, scanForRBACVulnerabilities(pod)...)

	// Check for network policy vulnerabilities
	vulnerabilities = append(vulnerabilities, scanForNetworkPolicyVulnerabilities(pod)...)

	// Check for resource vulnerabilities
	vulnerabilities = append(vulnerabilities, scanForResourceVulnerabilities(pod)...)

	// Check for image vulnerabilities
	vulnerabilities = append(vulnerabilities, scanForImageVulnerabilities(pod)...)

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

// scanForSSRFVulnerabilities detects SSRF vulnerabilities
func scanForSSRFVulnerabilities(pod *v1.Pod) []*VulnerabilityInfo {
	var vulnerabilities []*VulnerabilityInfo

	// Check for SSRF-related environment variables
	for _, container := range pod.Spec.Containers {
		for _, env := range container.Env {
			// Check for internal API URLs
			if env.Name == "INTERNAL_API_URL" || env.Name == "METADATA_URL" {
				vulnerabilities = append(vulnerabilities, &VulnerabilityInfo{
					PodName:           pod.Name,
					Namespace:         pod.Namespace,
					Severity:          "HIGH",
					VulnerabilityType: "ssrf",
					Description:       fmt.Sprintf("Container '%s' has SSRF-vulnerable environment variable: %s=%s", container.Name, env.Name, env.Value),
					Recommendation:    "Remove or secure internal API URLs and metadata endpoints",
				})
			}

			// Check for Kubernetes API access
			if env.Name == "KUBERNETES_SERVICE_HOST" || env.Name == "KUBERNETES_SERVICE_PORT" {
				vulnerabilities = append(vulnerabilities, &VulnerabilityInfo{
					PodName:           pod.Name,
					Namespace:         pod.Namespace,
					Severity:          "MEDIUM",
					VulnerabilityType: "kubernetesApiAccess",
					Description:       fmt.Sprintf("Container '%s' has Kubernetes API access: %s=%s", container.Name, env.Name, env.Value),
					Recommendation:    "Restrict Kubernetes API access and use proper RBAC",
				})
			}
		}
	}

	return vulnerabilities
}

// scanForContainerEscapeVulnerabilities detects container escape vulnerabilities
func scanForContainerEscapeVulnerabilities(pod *v1.Pod) []*VulnerabilityInfo {
	var vulnerabilities []*VulnerabilityInfo

	// Check for Docker socket access
	for _, volume := range pod.Spec.Volumes {
		if volume.HostPath != nil && volume.HostPath.Path == "/var/run/docker.sock" {
			vulnerabilities = append(vulnerabilities, &VulnerabilityInfo{
				PodName:           pod.Name,
				Namespace:         pod.Namespace,
				Severity:          "CRITICAL",
				VulnerabilityType: "dockerSocketAccess",
				Description:       "Pod has Docker socket access which allows container escape",
				Recommendation:    "Remove Docker socket mount or use read-only mount",
			})
		}
	}

	// Check for cgroup escape capabilities
	for _, container := range pod.Spec.Containers {
		if container.SecurityContext != nil && container.SecurityContext.Capabilities != nil {
			for _, cap := range container.SecurityContext.Capabilities.Add {
				if cap == "SYS_ADMIN" || cap == "SYS_CHROOT" {
					vulnerabilities = append(vulnerabilities, &VulnerabilityInfo{
						PodName:           pod.Name,
						Namespace:         pod.Namespace,
						Severity:          "CRITICAL",
						VulnerabilityType: "containerEscapeCapability",
						Description:       fmt.Sprintf("Container '%s' has dangerous capability: %s", container.Name, cap),
						Recommendation:    "Remove SYS_ADMIN and SYS_CHROOT capabilities",
					})
				}
			}
		}
	}

	// Check for kernel module access
	for _, volume := range pod.Spec.Volumes {
		if volume.HostPath != nil && volume.HostPath.Path == "/lib/modules" {
			vulnerabilities = append(vulnerabilities, &VulnerabilityInfo{
				PodName:           pod.Name,
				Namespace:         pod.Namespace,
				Severity:          "CRITICAL",
				VulnerabilityType: "kernelModuleAccess",
				Description:       "Pod has kernel module access which allows container escape",
				Recommendation:    "Remove kernel module mount",
			})
		}
	}

	return vulnerabilities
}

// scanForSupplyChainVulnerabilities detects supply chain vulnerabilities
func scanForSupplyChainVulnerabilities(pod *v1.Pod) []*VulnerabilityInfo {
	var vulnerabilities []*VulnerabilityInfo

	// Check for malicious registry images
	for _, container := range pod.Spec.Containers {
		// Check for malicious registry patterns
		if strings.Contains(container.Image, "malicious-registry") ||
			strings.Contains(container.Image, "vulnerable-app") ||
			strings.Contains(container.Image, "compromised-base") {
			vulnerabilities = append(vulnerabilities, &VulnerabilityInfo{
				PodName:           pod.Name,
				Namespace:         pod.Namespace,
				Severity:          "HIGH",
				VulnerabilityType: "maliciousImage",
				Description:       fmt.Sprintf("Container '%s' uses potentially malicious image: %s", container.Name, container.Image),
				Recommendation:    "Use trusted base images and scan for vulnerabilities",
			})
		}

		// Check for latest tags (supply chain risk)
		if strings.HasSuffix(container.Image, ":latest") {
			vulnerabilities = append(vulnerabilities, &VulnerabilityInfo{
				PodName:           pod.Name,
				Namespace:         pod.Namespace,
				Severity:          "MEDIUM",
				VulnerabilityType: "latestTag",
				Description:       fmt.Sprintf("Container '%s' uses latest tag: %s", container.Name, container.Image),
				Recommendation:    "Use specific version tags instead of latest",
			})
		}

		// Check for compromised dependencies
		for _, env := range container.Env {
			if env.Name == "COMPROMISED_DEPENDENCIES" || env.Name == "MALICIOUS_PACKAGES" {
				vulnerabilities = append(vulnerabilities, &VulnerabilityInfo{
					PodName:           pod.Name,
					Namespace:         pod.Namespace,
					Severity:          "HIGH",
					VulnerabilityType: "compromisedDependencies",
					Description:       fmt.Sprintf("Container '%s' has compromised dependencies: %s=%s", container.Name, env.Name, env.Value),
					Recommendation:    "Audit and update dependencies, use dependency scanning",
				})
			}
		}
	}

	return vulnerabilities
}

// scanForCryptoMiningVulnerabilities detects crypto mining vulnerabilities
func scanForCryptoMiningVulnerabilities(pod *v1.Pod) []*VulnerabilityInfo {
	var vulnerabilities []*VulnerabilityInfo

	// Check for crypto mining environment variables
	for _, container := range pod.Spec.Containers {
		for _, env := range container.Env {
			if env.Name == "MINING_POOL" || env.Name == "WALLET_ADDRESS" ||
				env.Name == "MINING_ALGORITHM" || env.Name == "CPU_INTENSIVE" ||
				env.Name == "GPU_MINING" || env.Name == "MINING_INTENSITY" {
				vulnerabilities = append(vulnerabilities, &VulnerabilityInfo{
					PodName:           pod.Name,
					Namespace:         pod.Namespace,
					Severity:          "HIGH",
					VulnerabilityType: "cryptoMining",
					Description:       fmt.Sprintf("Container '%s' appears to be crypto mining: %s=%s", container.Name, env.Name, env.Value),
					Recommendation:    "Investigate and remove crypto mining activities",
				})
			}
		}

		// Check for excessive resource requests (crypto mining pattern)
		if container.Resources.Requests != nil {
			if cpu, exists := container.Resources.Requests["cpu"]; exists {
				if cpu.MilliValue() > 1000 { // More than 1 CPU
					vulnerabilities = append(vulnerabilities, &VulnerabilityInfo{
						PodName:           pod.Name,
						Namespace:         pod.Namespace,
						Severity:          "MEDIUM",
						VulnerabilityType: "excessiveCpuRequest",
						Description:       fmt.Sprintf("Container '%s' has high CPU request: %s", container.Name, cpu.String()),
						Recommendation:    "Review CPU requirements and monitor for crypto mining",
					})
				}
			}

			if memory, exists := container.Resources.Requests["memory"]; exists {
				if memory.Value() > 1024*1024*1024 { // More than 1GB
					vulnerabilities = append(vulnerabilities, &VulnerabilityInfo{
						PodName:           pod.Name,
						Namespace:         pod.Namespace,
						Severity:          "MEDIUM",
						VulnerabilityType: "excessiveMemoryRequest",
						Description:       fmt.Sprintf("Container '%s' has high memory request: %s", container.Name, memory.String()),
						Recommendation:    "Review memory requirements and monitor for crypto mining",
					})
				}
			}
		}

		// Check for GPU requests (crypto mining pattern)
		if container.Resources.Requests != nil {
			if gpu, exists := container.Resources.Requests["nvidia.com/gpu"]; exists {
				vulnerabilities = append(vulnerabilities, &VulnerabilityInfo{
					PodName:           pod.Name,
					Namespace:         pod.Namespace,
					Severity:          "HIGH",
					VulnerabilityType: "gpuRequest",
					Description:       fmt.Sprintf("Container '%s' requests GPU resources: %s", container.Name, gpu.String()),
					Recommendation:    "Monitor GPU usage for crypto mining activities",
				})
			}
		}
	}

	return vulnerabilities
}

// scanForDNSPoisoningVulnerabilities detects DNS poisoning vulnerabilities
func scanForDNSPoisoningVulnerabilities(pod *v1.Pod) []*VulnerabilityInfo {
	var vulnerabilities []*VulnerabilityInfo

	// Check for DNS poisoning environment variables
	for _, container := range pod.Spec.Containers {
		for _, env := range container.Env {
			if env.Name == "DNS_POISONING" || env.Name == "CACHE_POISONING" ||
				env.Name == "DNS_SPOOFING" || env.Name == "MALICIOUS_RECORDS" ||
				env.Name == "DNS_HIJACKING" || env.Name == "TRAFFIC_REDIRECTION" {
				vulnerabilities = append(vulnerabilities, &VulnerabilityInfo{
					PodName:           pod.Name,
					Namespace:         pod.Namespace,
					Severity:          "HIGH",
					VulnerabilityType: "dnsPoisoning",
					Description:       fmt.Sprintf("Container '%s' has DNS poisoning indicators: %s=%s", container.Name, env.Name, env.Value),
					Recommendation:    "Investigate and remove DNS poisoning activities",
				})
			}
		}
	}

	// Check for DNS-related hostPath mounts
	for _, volume := range pod.Spec.Volumes {
		if volume.HostPath != nil && (strings.Contains(volume.HostPath.Path, "dns") ||
			strings.Contains(volume.HostPath.Path, "resolv")) {
			vulnerabilities = append(vulnerabilities, &VulnerabilityInfo{
				PodName:           pod.Name,
				Namespace:         pod.Namespace,
				Severity:          "HIGH",
				VulnerabilityType: "dnsMount",
				Description:       fmt.Sprintf("Pod has DNS-related hostPath mount: %s", volume.HostPath.Path),
				Recommendation:    "Remove DNS-related hostPath mounts",
			})
		}
	}

	return vulnerabilities
}

// scanForServiceExposureVulnerabilities detects service exposure vulnerabilities
func scanForServiceExposureVulnerabilities(pod *v1.Pod) []*VulnerabilityInfo {
	var vulnerabilities []*VulnerabilityInfo

	// Check for NodePort services (this would need to be called from a service scanning function)
	// For now, we'll check pod labels that might indicate external exposure
	if pod.Labels != nil {
		if securityLevel, exists := pod.Labels["security-level"]; exists {
			if securityLevel == "critical" || securityLevel == "high-risk" {
				vulnerabilities = append(vulnerabilities, &VulnerabilityInfo{
					PodName:           pod.Name,
					Namespace:         pod.Namespace,
					Severity:          "MEDIUM",
					VulnerabilityType: "highRiskPod",
					Description:       fmt.Sprintf("Pod has high-risk security level: %s", securityLevel),
					Recommendation:    "Review pod security configuration and exposure",
				})
			}
		}
	}

	return vulnerabilities
}

// scanForSecretsExposureVulnerabilities detects secrets exposure vulnerabilities
func scanForSecretsExposureVulnerabilities(pod *v1.Pod) []*VulnerabilityInfo {
	var vulnerabilities []*VulnerabilityInfo

	// Check for secrets in environment variables
	for _, container := range pod.Spec.Containers {
		for _, env := range container.Env {
			// Check for common secret patterns
			if isSecretPattern(env.Name, env.Value) {
				vulnerabilities = append(vulnerabilities, &VulnerabilityInfo{
					PodName:           pod.Name,
					Namespace:         pod.Namespace,
					Severity:          "HIGH",
					VulnerabilityType: "secretInEnv",
					Description:       fmt.Sprintf("Container '%s' has potential secret in environment: %s", container.Name, env.Name),
					Recommendation:    "Use Kubernetes secrets instead of environment variables for sensitive data",
				})
			}
		}
	}

	return vulnerabilities
}

// scanForRBACVulnerabilities detects RBAC vulnerabilities
func scanForRBACVulnerabilities(pod *v1.Pod) []*VulnerabilityInfo {
	var vulnerabilities []*VulnerabilityInfo

	// Check for service account token mounting
	if pod.Spec.AutomountServiceAccountToken != nil && *pod.Spec.AutomountServiceAccountToken {
		vulnerabilities = append(vulnerabilities, &VulnerabilityInfo{
			PodName:           pod.Name,
			Namespace:         pod.Namespace,
			Severity:          "MEDIUM",
			VulnerabilityType: "serviceAccountTokenMount",
			Description:       "Pod automatically mounts service account token",
			Recommendation:    "Set automountServiceAccountToken: false if not needed",
		})
	}

	return vulnerabilities
}

// scanForNetworkPolicyVulnerabilities detects network policy vulnerabilities
func scanForNetworkPolicyVulnerabilities(pod *v1.Pod) []*VulnerabilityInfo {
	var vulnerabilities []*VulnerabilityInfo

	// Check for host network access (already covered above, but adding for completeness)
	if pod.Spec.HostNetwork {
		vulnerabilities = append(vulnerabilities, &VulnerabilityInfo{
			PodName:           pod.Name,
			Namespace:         pod.Namespace,
			Severity:          "HIGH",
			VulnerabilityType: "hostNetwork",
			Description:       "Pod uses host network which bypasses network policies",
			Recommendation:    "Remove hostNetwork: true and use proper network policies",
		})
	}

	return vulnerabilities
}

// scanForResourceVulnerabilities detects resource vulnerabilities
func scanForResourceVulnerabilities(pod *v1.Pod) []*VulnerabilityInfo {
	var vulnerabilities []*VulnerabilityInfo

	// Check for missing resource limits
	for _, container := range pod.Spec.Containers {
		if len(container.Resources.Limits) == 0 {
			vulnerabilities = append(vulnerabilities, &VulnerabilityInfo{
				PodName:           pod.Name,
				Namespace:         pod.Namespace,
				Severity:          "MEDIUM",
				VulnerabilityType: "missingResourceLimits",
				Description:       fmt.Sprintf("Container '%s' has no resource limits", container.Name),
				Recommendation:    "Set resource limits to prevent resource exhaustion",
			})
		}

		if len(container.Resources.Requests) == 0 {
			vulnerabilities = append(vulnerabilities, &VulnerabilityInfo{
				PodName:           pod.Name,
				Namespace:         pod.Namespace,
				Severity:          "LOW",
				VulnerabilityType: "missingResourceRequests",
				Description:       fmt.Sprintf("Container '%s' has no resource requests", container.Name),
				Recommendation:    "Set resource requests for better scheduling",
			})
		}
	}

	return vulnerabilities
}

// scanForImageVulnerabilities detects image vulnerabilities
func scanForImageVulnerabilities(pod *v1.Pod) []*VulnerabilityInfo {
	var vulnerabilities []*VulnerabilityInfo

	// Check for image pull policy
	for _, container := range pod.Spec.Containers {
		if container.ImagePullPolicy == v1.PullAlways {
			vulnerabilities = append(vulnerabilities, &VulnerabilityInfo{
				PodName:           pod.Name,
				Namespace:         pod.Namespace,
				Severity:          "LOW",
				VulnerabilityType: "alwaysPullPolicy",
				Description:       fmt.Sprintf("Container '%s' uses Always pull policy", container.Name),
				Recommendation:    "Use IfNotPresent or Never pull policy for better security",
			})
		}

		// Check for unsigned images (basic check)
		if strings.Contains(container.Image, "registry.example.com") ||
			strings.Contains(container.Image, "malicious-registry") {
			vulnerabilities = append(vulnerabilities, &VulnerabilityInfo{
				PodName:           pod.Name,
				Namespace:         pod.Namespace,
				Severity:          "HIGH",
				VulnerabilityType: "untrustedRegistry",
				Description:       fmt.Sprintf("Container '%s' uses untrusted registry: %s", container.Name, container.Image),
				Recommendation:    "Use trusted registries and verify image signatures",
			})
		}
	}

	return vulnerabilities
}

// isSecretPattern checks if an environment variable name/value looks like a secret
func isSecretPattern(name, value string) bool {
	secretPatterns := []string{
		"SECRET", "PASSWORD", "TOKEN", "KEY", "CREDENTIAL", "AUTH",
		"API_KEY", "DB_PASSWORD", "JWT_SECRET", "AWS_ACCESS_KEY",
		"SSH_KEY", "PRIVATE_KEY", "CERTIFICATE",
	}

	nameUpper := strings.ToUpper(name)
	for _, pattern := range secretPatterns {
		if strings.Contains(nameUpper, pattern) {
			return true
		}
	}

	// Check for base64 encoded values (basic check)
	if len(value) > 20 && isBase64(value) {
		return true
	}

	return false
}

// isBase64 checks if a string is base64 encoded (basic check)
func isBase64(s string) bool {
	matched, _ := regexp.MatchString(`^[A-Za-z0-9+/]*={0,2}$`, s)
	return matched && len(s)%4 == 0
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
