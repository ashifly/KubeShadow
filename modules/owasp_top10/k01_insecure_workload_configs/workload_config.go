package workload_config

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"kubeshadow/pkg/logger"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// WorkloadFinding represents a security finding in a workload
type WorkloadFinding struct {
	WorkloadName       string          `json:"workloadName"`
	WorkloadType       string          `json:"workloadType"`
	Namespace          string          `json:"namespace"`
	Severity           string          `json:"severity"`
	RiskScore          float64         `json:"riskScore"`
	Vulnerabilities    []Vulnerability `json:"vulnerabilities"`
	Remediation        Remediation     `json:"remediation"`
	HostExposure       bool            `json:"hostExposure"`
	ServiceAccount     string          `json:"serviceAccount"`
	NamespaceSensitive bool            `json:"namespaceSensitive"`
}

// Vulnerability represents a specific security vulnerability
type Vulnerability struct {
	Type        string  `json:"type"`
	Description string  `json:"description"`
	Severity    string  `json:"severity"`
	CVSS        float64 `json:"cvss"`
}

// Remediation provides fix suggestions
type Remediation struct {
	Description      string `json:"description"`
	OPAPolicy        string `json:"opaPolicy"`
	GatekeeperPolicy string `json:"gatekeeperPolicy"`
	KubectlApply     string `json:"kubectlApply"`
}

// WorkloadConfigScanner scans workloads for insecure configurations
type WorkloadConfigScanner struct {
	clientset *kubernetes.Clientset
	ctx       context.Context
}

// NewWorkloadConfigScanner creates a new scanner instance
func NewWorkloadConfigScanner(ctx context.Context, kubeconfig string) (*WorkloadConfigScanner, error) {
	config, err := getKubeConfig(kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("failed to get kubeconfig: %v", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create clientset: %v", err)
	}

	return &WorkloadConfigScanner{
		clientset: clientset,
		ctx:       ctx,
	}, nil
}

// ScanWorkloads performs comprehensive workload security scanning
func (w *WorkloadConfigScanner) ScanWorkloads() ([]WorkloadFinding, error) {
	var findings []WorkloadFinding

	// Scan Pods
	podFindings, err := w.scanPods()
	if err != nil {
		return nil, fmt.Errorf("failed to scan pods: %v", err)
	}
	findings = append(findings, podFindings...)

	// Scan Deployments
	deploymentFindings, err := w.scanDeployments()
	if err != nil {
		return nil, fmt.Errorf("failed to scan deployments: %v", err)
	}
	findings = append(findings, deploymentFindings...)

	// Scan StatefulSets
	statefulSetFindings, err := w.scanStatefulSets()
	if err != nil {
		return nil, fmt.Errorf("failed to scan statefulsets: %v", err)
	}
	findings = append(findings, statefulSetFindings...)

	// Scan DaemonSets
	daemonSetFindings, err := w.scanDaemonSets()
	if err != nil {
		return nil, fmt.Errorf("failed to scan daemonsets: %v", err)
	}
	findings = append(findings, daemonSetFindings...)

	return findings, nil
}

// scanPods scans all pods for security issues
func (w *WorkloadConfigScanner) scanPods() ([]WorkloadFinding, error) {
	var findings []WorkloadFinding

	pods, err := w.clientset.CoreV1().Pods("").List(w.ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	for _, pod := range pods.Items {
		finding := w.analyzePodSpec(pod.Spec, pod.Name, "Pod", pod.Namespace, pod.Spec.ServiceAccountName)
		if finding != nil {
			findings = append(findings, *finding)
		}
	}

	return findings, nil
}

// scanDeployments scans all deployments for security issues
func (w *WorkloadConfigScanner) scanDeployments() ([]WorkloadFinding, error) {
	var findings []WorkloadFinding

	deployments, err := w.clientset.AppsV1().Deployments("").List(w.ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	for _, deployment := range deployments.Items {
		finding := w.analyzePodSpec(deployment.Spec.Template.Spec, deployment.Name, "Deployment", deployment.Namespace, deployment.Spec.Template.Spec.ServiceAccountName)
		if finding != nil {
			findings = append(findings, *finding)
		}
	}

	return findings, nil
}

// scanStatefulSets scans all statefulsets for security issues
func (w *WorkloadConfigScanner) scanStatefulSets() ([]WorkloadFinding, error) {
	var findings []WorkloadFinding

	statefulSets, err := w.clientset.AppsV1().StatefulSets("").List(w.ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	for _, statefulSet := range statefulSets.Items {
		finding := w.analyzePodSpec(statefulSet.Spec.Template.Spec, statefulSet.Name, "StatefulSet", statefulSet.Namespace, statefulSet.Spec.Template.Spec.ServiceAccountName)
		if finding != nil {
			findings = append(findings, *finding)
		}
	}

	return findings, nil
}

// scanDaemonSets scans all daemonsets for security issues
func (w *WorkloadConfigScanner) scanDaemonSets() ([]WorkloadFinding, error) {
	var findings []WorkloadFinding

	daemonSets, err := w.clientset.AppsV1().DaemonSets("").List(w.ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	for _, daemonSet := range daemonSets.Items {
		finding := w.analyzePodSpec(daemonSet.Spec.Template.Spec, daemonSet.Name, "DaemonSet", daemonSet.Namespace, daemonSet.Spec.Template.Spec.ServiceAccountName)
		if finding != nil {
			findings = append(findings, *finding)
		}
	}

	return findings, nil
}

// analyzePodSpec analyzes a PodSpec for security vulnerabilities
func (w *WorkloadConfigScanner) analyzePodSpec(spec corev1.PodSpec, name, workloadType, namespace, serviceAccount string) *WorkloadFinding {
	var vulnerabilities []Vulnerability
	riskScore := 0.0
	hostExposure := false

	// Check for privileged containers
	for _, container := range spec.Containers {
		if container.SecurityContext != nil && container.SecurityContext.Privileged != nil && *container.SecurityContext.Privileged {
			vulnerabilities = append(vulnerabilities, Vulnerability{
				Type:        "privileged",
				Description: fmt.Sprintf("Container '%s' is running in privileged mode", container.Name),
				Severity:    "CRITICAL",
				CVSS:        9.8,
			})
			riskScore += 9.8
		}

		// Check for runAsUser: 0 (root)
		if container.SecurityContext != nil && container.SecurityContext.RunAsUser != nil && *container.SecurityContext.RunAsUser == 0 {
			vulnerabilities = append(vulnerabilities, Vulnerability{
				Type:        "runAsUser",
				Description: fmt.Sprintf("Container '%s' is running as root user", container.Name),
				Severity:    "HIGH",
				CVSS:        7.5,
			})
			riskScore += 7.5
		}

		// Check for allowPrivilegeEscalation: true
		if container.SecurityContext != nil && container.SecurityContext.AllowPrivilegeEscalation != nil && *container.SecurityContext.AllowPrivilegeEscalation {
			vulnerabilities = append(vulnerabilities, Vulnerability{
				Type:        "allowPrivilegeEscalation",
				Description: fmt.Sprintf("Container '%s' allows privilege escalation", container.Name),
				Severity:    "HIGH",
				CVSS:        7.2,
			})
			riskScore += 7.2
		}

		// Check for excessive capabilities
		if container.SecurityContext != nil && container.SecurityContext.Capabilities != nil {
			for _, cap := range container.SecurityContext.Capabilities.Add {
				if cap == "ALL" {
					vulnerabilities = append(vulnerabilities, Vulnerability{
						Type:        "excessiveCapabilities",
						Description: fmt.Sprintf("Container '%s' has ALL capabilities", container.Name),
						Severity:    "HIGH",
						CVSS:        8.1,
					})
					riskScore += 8.1
				}
			}
		}

		// Check for imagePullPolicy: Always
		if container.ImagePullPolicy == corev1.PullAlways {
			vulnerabilities = append(vulnerabilities, Vulnerability{
				Type:        "imagePullPolicy",
				Description: fmt.Sprintf("Container '%s' uses imagePullPolicy: Always", container.Name),
				Severity:    "MEDIUM",
				CVSS:        4.3,
			})
			riskScore += 4.3
		}
	}

	// Check pod-level security context
	if spec.SecurityContext != nil {
		if spec.SecurityContext.RunAsUser != nil && *spec.SecurityContext.RunAsUser == 0 {
			vulnerabilities = append(vulnerabilities, Vulnerability{
				Type:        "podRunAsUser",
				Description: "Pod is configured to run as root user",
				Severity:    "HIGH",
				CVSS:        7.5,
			})
			riskScore += 7.5
		}

		if spec.SecurityContext.RunAsNonRoot != nil && !*spec.SecurityContext.RunAsNonRoot {
			vulnerabilities = append(vulnerabilities, Vulnerability{
				Type:        "runAsNonRoot",
				Description: "Pod is configured to run as root (runAsNonRoot: false)",
				Severity:    "HIGH",
				CVSS:        7.5,
			})
			riskScore += 7.5
		}
	}

	// Check for hostNetwork
	if spec.HostNetwork {
		vulnerabilities = append(vulnerabilities, Vulnerability{
			Type:        "hostNetwork",
			Description: "Pod is using host network",
			Severity:    "HIGH",
			CVSS:        7.2,
		})
		riskScore += 7.2
		hostExposure = true
	}

	// Check for hostPID
	if spec.HostPID {
		vulnerabilities = append(vulnerabilities, Vulnerability{
			Type:        "hostPID",
			Description: "Pod is sharing host PID namespace",
			Severity:    "HIGH",
			CVSS:        7.2,
		})
		riskScore += 7.2
		hostExposure = true
	}

	// Check for hostIPC
	if spec.HostIPC {
		vulnerabilities = append(vulnerabilities, Vulnerability{
			Type:        "hostIPC",
			Description: "Pod is sharing host IPC namespace",
			Severity:    "HIGH",
			CVSS:        7.2,
		})
		riskScore += 7.2
		hostExposure = true
	}

	// Check for dangerous hostPath mounts
	for _, volume := range spec.Volumes {
		if volume.HostPath != nil {
			path := volume.HostPath.Path
			if isDangerousHostPath(path) {
				vulnerabilities = append(vulnerabilities, Vulnerability{
					Type:        "hostPath",
					Description: fmt.Sprintf("Pod has dangerous hostPath mount: %s", path),
					Severity:    "CRITICAL",
					CVSS:        9.1,
				})
				riskScore += 9.1
				hostExposure = true
			}
		}
	}

	// If no vulnerabilities found, return nil
	if len(vulnerabilities) == 0 {
		return nil
	}

	// Determine overall severity
	severity := "LOW"
	if riskScore >= 9.0 {
		severity = "CRITICAL"
	} else if riskScore >= 7.0 {
		severity = "HIGH"
	} else if riskScore >= 4.0 {
		severity = "MEDIUM"
	}

	// Check if namespace is sensitive
	namespaceSensitive := isSensitiveNamespace(namespace)

	// Generate remediation
	remediation := w.generateRemediation(vulnerabilities, namespace)

	return &WorkloadFinding{
		WorkloadName:       name,
		WorkloadType:       workloadType,
		Namespace:          namespace,
		Severity:           severity,
		RiskScore:          riskScore,
		Vulnerabilities:    vulnerabilities,
		Remediation:        remediation,
		HostExposure:       hostExposure,
		ServiceAccount:     serviceAccount,
		NamespaceSensitive: namespaceSensitive,
	}
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

// isSensitiveNamespace checks if a namespace is sensitive
func isSensitiveNamespace(namespace string) bool {
	sensitiveNamespaces := []string{
		"kube-system",
		"kube-public",
		"kube-node-lease",
		"default",
		"kube-apiserver",
		"kube-controller-manager",
		"kube-scheduler",
		"etcd",
		"kube-proxy",
		"kube-flannel",
		"kube-dns",
		"kube-dashboard",
		"monitoring",
		"logging",
		"security",
		"gatekeeper-system",
		"opa",
		"falco",
		"twistlock",
		"aqua",
		"neuvector",
	}

	for _, sensitiveNS := range sensitiveNamespaces {
		if namespace == sensitiveNS {
			return true
		}
	}

	return false
}

// generateRemediation generates remediation suggestions
func (w *WorkloadConfigScanner) generateRemediation(vulnerabilities []Vulnerability, namespace string) Remediation {
	var opaPolicy strings.Builder
	var gatekeeperPolicy strings.Builder
	var kubectlApply strings.Builder

	opaPolicy.WriteString("# OPA Policy for Pod Security\n")
	opaPolicy.WriteString("package kubernetes.admission\n\n")
	opaPolicy.WriteString("deny[msg] {\n")
	opaPolicy.WriteString("    input.request.kind.kind == \"Pod\"\n")
	opaPolicy.WriteString("    input.request.operation == \"CREATE\"\n")

	gatekeeperPolicy.WriteString("apiVersion: templates.gatekeeper.sh/v1beta1\n")
	gatekeeperPolicy.WriteString("kind: ConstraintTemplate\n")
	gatekeeperPolicy.WriteString("metadata:\n")
	gatekeeperPolicy.WriteString("  name: k8spspsecuritycontext\n")
	gatekeeperPolicy.WriteString("spec:\n")
	gatekeeperPolicy.WriteString("  crd:\n")
	gatekeeperPolicy.WriteString("    spec:\n")
	gatekeeperPolicy.WriteString("      names:\n")
	gatekeeperPolicy.WriteString("        kind: K8sPSPSecurityContext\n")

	// Generate specific remediation based on vulnerabilities
	for _, vuln := range vulnerabilities {
		switch vuln.Type {
		case "privileged":
			opaPolicy.WriteString("    input.request.object.spec.containers[_].securityContext.privileged == true\n")
			opaPolicy.WriteString("    msg := \"Privileged containers are not allowed\"\n")
			opaPolicy.WriteString("}\n\n")
		case "runAsUser", "podRunAsUser":
			opaPolicy.WriteString("    input.request.object.spec.securityContext.runAsUser == 0\n")
			opaPolicy.WriteString("    msg := \"Running as root user is not allowed\"\n")
			opaPolicy.WriteString("}\n\n")
		case "allowPrivilegeEscalation":
			opaPolicy.WriteString("    input.request.object.spec.containers[_].securityContext.allowPrivilegeEscalation == true\n")
			opaPolicy.WriteString("    msg := \"Privilege escalation is not allowed\"\n")
			opaPolicy.WriteString("}\n\n")
		case "hostNetwork":
			opaPolicy.WriteString("    input.request.object.spec.hostNetwork == true\n")
			opaPolicy.WriteString("    msg := \"Host network is not allowed\"\n")
			opaPolicy.WriteString("}\n\n")
		case "hostPath":
			opaPolicy.WriteString("    input.request.object.spec.volumes[_].hostPath\n")
			opaPolicy.WriteString("    msg := \"Host path volumes are not allowed\"\n")
			opaPolicy.WriteString("}\n\n")
		}
	}

	// Generate kubectl apply command
	kubectlApply.WriteString("# Apply Pod Security Policy\n")
	kubectlApply.WriteString("kubectl apply -f - <<EOF\n")
	kubectlApply.WriteString("apiVersion: v1\n")
	kubectlApply.WriteString("kind: Namespace\n")
	kubectlApply.WriteString("metadata:\n")
	kubectlApply.WriteString(fmt.Sprintf("  name: %s\n", namespace))
	kubectlApply.WriteString("  labels:\n")
	kubectlApply.WriteString("    pod-security.kubernetes.io/enforce: restricted\n")
	kubectlApply.WriteString("    pod-security.kubernetes.io/audit: restricted\n")
	kubectlApply.WriteString("    pod-security.kubernetes.io/warn: restricted\n")
	kubectlApply.WriteString("EOF\n")

	return Remediation{
		Description:      "Apply Pod Security Standards and OPA/Gatekeeper policies to enforce secure configurations",
		OPAPolicy:        opaPolicy.String(),
		GatekeeperPolicy: gatekeeperPolicy.String(),
		KubectlApply:     kubectlApply.String(),
	}
}

// getKubeConfig creates a Kubernetes config
func getKubeConfig(kubeconfig string) (*rest.Config, error) {
	if kubeconfig != "" {
		return clientcmd.BuildConfigFromFlags("", kubeconfig)
	}
	return rest.InClusterConfig()
}

// SaveFindingsToFile saves findings to insecure_workloads.json
func (w *WorkloadConfigScanner) SaveFindingsToFile(findings []WorkloadFinding, outputPath string) error {
	// Create output directory if it doesn't exist
	dir := filepath.Dir(outputPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %v", err)
	}

	// For now, we'll use a simple text format
	// In a real implementation, you'd use json.Marshal
	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %v", err)
	}
	defer file.Close()

	// Write findings summary
	file.WriteString("=== INSECURE WORKLOAD CONFIGURATIONS ===\n\n")
	file.WriteString(fmt.Sprintf("Total Findings: %d\n\n", len(findings)))

	// Group by severity
	critical := 0
	high := 0
	medium := 0
	low := 0

	for _, finding := range findings {
		switch finding.Severity {
		case "CRITICAL":
			critical++
		case "HIGH":
			high++
		case "MEDIUM":
			medium++
		case "LOW":
			low++
		}
	}

	file.WriteString("=== SEVERITY BREAKDOWN ===\n")
	file.WriteString(fmt.Sprintf("🔴 Critical: %d\n", critical))
	file.WriteString(fmt.Sprintf("🟠 High: %d\n", high))
	file.WriteString(fmt.Sprintf("🟡 Medium: %d\n", medium))
	file.WriteString(fmt.Sprintf("🟢 Low: %d\n", low))
	file.WriteString("\n")

	// Write detailed findings
	for _, finding := range findings {
		file.WriteString(fmt.Sprintf("=== %s: %s ===\n", finding.WorkloadType, finding.WorkloadName))
		file.WriteString(fmt.Sprintf("Namespace: %s\n", finding.Namespace))
		file.WriteString(fmt.Sprintf("Severity: %s\n", finding.Severity))
		file.WriteString(fmt.Sprintf("Risk Score: %.2f\n", finding.RiskScore))
		file.WriteString(fmt.Sprintf("Host Exposure: %t\n", finding.HostExposure))
		file.WriteString(fmt.Sprintf("Service Account: %s\n", finding.ServiceAccount))
		file.WriteString(fmt.Sprintf("Namespace Sensitive: %t\n", finding.NamespaceSensitive))
		file.WriteString("\nVulnerabilities:\n")

		for _, vuln := range finding.Vulnerabilities {
			file.WriteString(fmt.Sprintf("  • %s: %s (CVSS: %.1f)\n", vuln.Type, vuln.Description, vuln.CVSS))
		}

		file.WriteString("\nRemediation:\n")
		file.WriteString(fmt.Sprintf("  %s\n", finding.Remediation.Description))
		file.WriteString("\nOPA Policy:\n")
		file.WriteString(fmt.Sprintf("  %s\n", finding.Remediation.OPAPolicy))
		file.WriteString("\nKubectl Apply:\n")
		file.WriteString(fmt.Sprintf("  %s\n", finding.Remediation.KubectlApply))
		file.WriteString("\n" + strings.Repeat("=", 80) + "\n\n")
	}

	logger.Info("✅ Workload security findings saved to: %s", outputPath)
	return nil
}
