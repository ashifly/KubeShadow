package k10_vulnerabilities

import (
	"context"
	"fmt"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// NewVulnerabilityScanner creates a new vulnerability scanner
func NewVulnerabilityScanner(kubeconfig string, namespace string, labMode bool) (*VulnerabilityScanner, error) {
	var config *rest.Config
	var err error

	if kubeconfig != "" {
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
	} else {
		config, err = rest.InClusterConfig()
		if err != nil {
			config, err = clientcmd.BuildConfigFromFlags("", clientcmd.RecommendedHomeFile)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("failed to create kubeconfig: %w", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create kubernetes client: %w", err)
	}

	return &VulnerabilityScanner{
		client:    clientset,
		namespace: namespace,
		ctx:       context.Background(),
		labMode:   labMode,
	}, nil
}

// DetectKubernetesVersion detects Kubernetes version
func (vs *VulnerabilityScanner) DetectKubernetesVersion() (KubernetesVersion, []VulnerabilityFinding, error) {
	var findings []VulnerabilityFinding
	version := KubernetesVersion{}

	// Get server version
	serverVersion, err := vs.client.Discovery().ServerVersion()
	if err != nil {
		return version, findings, fmt.Errorf("failed to get server version: %w", err)
	}

	version.Major = serverVersion.Major
	version.Minor = serverVersion.Minor
	version.GitVersion = serverVersion.GitVersion
	version.GitCommit = serverVersion.GitCommit
	version.BuildDate = serverVersion.BuildDate
	version.GoVersion = serverVersion.GoVersion
	version.Compiler = serverVersion.Compiler
	version.Platform = serverVersion.Platform

	// Check for outdated Kubernetes version
	if vs.isOutdatedKubernetesVersion(version.GitVersion) {
		findings = append(findings, VulnerabilityFinding{
			ID:          "vuln-001",
			Type:        "kubernetes-version",
			Severity:    "high",
			Title:       "Outdated Kubernetes Version",
			Description: fmt.Sprintf("Kubernetes version %s is outdated and may contain security vulnerabilities.", version.GitVersion),
			Resource:    "cluster",
			Namespace:   "all",
			RiskScore:   8.0,
			Remediation: "Upgrade Kubernetes to the latest stable version.",
			Timestamp:   time.Now(),
			Metadata: map[string]string{
				"current_version":     version.GitVersion,
				"recommended_version": "v1.28.0+",
			},
		})
	}

	return version, findings, nil
}

// DetectNodeVulnerabilities detects node vulnerabilities
func (vs *VulnerabilityScanner) DetectNodeVulnerabilities() ([]NodeInfo, []VulnerabilityFinding, error) {
	var findings []VulnerabilityFinding
	var nodes []NodeInfo

	// List all nodes
	nodeList, err := vs.client.CoreV1().Nodes().List(vs.ctx, metav1.ListOptions{})
	if err != nil {
		return nodes, findings, fmt.Errorf("failed to list nodes: %w", err)
	}

	for _, node := range nodeList.Items {
		nodeInfo := NodeInfo{
			Name:           node.Name,
			Version:        node.Status.NodeInfo.KubeletVersion,
			OS:             node.Status.NodeInfo.OperatingSystem,
			Architecture:   node.Status.NodeInfo.Architecture,
			Runtime:        node.Status.NodeInfo.ContainerRuntimeVersion,
			KubeletVersion: node.Status.NodeInfo.KubeletVersion,
			Vulnerable:     false,
			CVEs:           []CVEInfo{},
			Metadata:       make(map[string]string),
		}

		// Check for outdated kubelet version
		if vs.isOutdatedKubeletVersion(nodeInfo.KubeletVersion) {
			nodeInfo.Vulnerable = true
			findings = append(findings, VulnerabilityFinding{
				ID:          "vuln-002",
				Type:        "kubelet-version",
				Severity:    "high",
				Title:       "Outdated Kubelet Version",
				Description: fmt.Sprintf("Node %s has outdated kubelet version %s.", node.Name, nodeInfo.KubeletVersion),
				Resource:    fmt.Sprintf("node/%s", node.Name),
				Namespace:   "",
				RiskScore:   7.5,
				Remediation: "Upgrade kubelet to the latest version.",
				Timestamp:   time.Now(),
				Metadata: map[string]string{
					"node_name":       node.Name,
					"kubelet_version": nodeInfo.KubeletVersion,
				},
			})
		}

		// Check for outdated container runtime
		if vs.isOutdatedRuntime(nodeInfo.Runtime) {
			nodeInfo.Vulnerable = true
			findings = append(findings, VulnerabilityFinding{
				ID:          "vuln-003",
				Type:        "runtime-version",
				Severity:    "medium",
				Title:       "Outdated Container Runtime",
				Description: fmt.Sprintf("Node %s has outdated container runtime %s.", node.Name, nodeInfo.Runtime),
				Resource:    fmt.Sprintf("node/%s", node.Name),
				Namespace:   "",
				RiskScore:   6.0,
				Remediation: "Upgrade container runtime to the latest version.",
				Timestamp:   time.Now(),
				Metadata: map[string]string{
					"node_name":       node.Name,
					"runtime_version": nodeInfo.Runtime,
				},
			})
		}

		// Simulate CVE detection
		cves := vs.detectNodeCVEs(nodeInfo)
		nodeInfo.CVEs = cves
		if len(cves) > 0 {
			nodeInfo.Vulnerable = true
		}

		nodes = append(nodes, nodeInfo)
	}

	return nodes, findings, nil
}

// DetectComponentVulnerabilities detects component vulnerabilities
func (vs *VulnerabilityScanner) DetectComponentVulnerabilities() ([]ComponentInfo, []VulnerabilityFinding, error) {
	var findings []VulnerabilityFinding
	var components []ComponentInfo

	// Simulate component detection
	simulatedComponents := []ComponentInfo{
		{
			Name:          "kube-apiserver",
			Type:          "control-plane",
			Version:       "v1.25.0",
			LatestVersion: "v1.28.0",
			Outdated:      true,
			Vulnerable:    true,
			RiskLevel:     "high",
			CVEs:          []CVEInfo{},
			Metadata:      make(map[string]string),
		},
		{
			Name:          "kube-controller-manager",
			Type:          "control-plane",
			Version:       "v1.25.0",
			LatestVersion: "v1.28.0",
			Outdated:      true,
			Vulnerable:    true,
			RiskLevel:     "high",
			CVEs:          []CVEInfo{},
			Metadata:      make(map[string]string),
		},
		{
			Name:          "kube-scheduler",
			Type:          "control-plane",
			Version:       "v1.25.0",
			LatestVersion: "v1.28.0",
			Outdated:      true,
			Vulnerable:    true,
			RiskLevel:     "high",
			CVEs:          []CVEInfo{},
			Metadata:      make(map[string]string),
		},
		{
			Name:          "kube-proxy",
			Type:          "control-plane",
			Version:       "v1.25.0",
			LatestVersion: "v1.28.0",
			Outdated:      true,
			Vulnerable:    true,
			RiskLevel:     "medium",
			CVEs:          []CVEInfo{},
			Metadata:      make(map[string]string),
		},
	}

	for _, component := range simulatedComponents {
		if component.Outdated {
			findings = append(findings, VulnerabilityFinding{
				ID:          "vuln-004",
				Type:        "component-version",
				Severity:    component.RiskLevel,
				Title:       "Outdated Component Version",
				Description: fmt.Sprintf("Component %s version %s is outdated.", component.Name, component.Version),
				Resource:    fmt.Sprintf("component/%s", component.Name),
				Namespace:   "",
				RiskScore:   vs.getRiskScore(component.RiskLevel),
				Remediation: fmt.Sprintf("Upgrade %s to version %s.", component.Name, component.LatestVersion),
				Timestamp:   time.Now(),
				Metadata: map[string]string{
					"component_name":  component.Name,
					"current_version": component.Version,
					"latest_version":  component.LatestVersion,
				},
			})
		}

		// Simulate CVE detection
		cves := vs.detectComponentCVEs(component)
		component.CVEs = cves
		if len(cves) > 0 {
			component.Vulnerable = true
		}

		components = append(components, component)
	}

	return components, findings, nil
}

// DetectAddonVulnerabilities detects addon vulnerabilities
func (vs *VulnerabilityScanner) DetectAddonVulnerabilities() ([]AddonInfo, []VulnerabilityFinding, error) {
	var findings []VulnerabilityFinding
	var addons []AddonInfo

	// Simulate addon detection
	simulatedAddons := []AddonInfo{
		{
			Name:          "nginx-ingress",
			Type:          "ingress",
			Version:       "v1.2.0",
			LatestVersion: "v1.8.0",
			Outdated:      true,
			Vulnerable:    true,
			RiskLevel:     "medium",
			CVEs:          []CVEInfo{},
			Metadata:      make(map[string]string),
		},
		{
			Name:          "calico",
			Type:          "cni",
			Version:       "v3.20.0",
			LatestVersion: "v3.26.0",
			Outdated:      true,
			Vulnerable:    true,
			RiskLevel:     "high",
			CVEs:          []CVEInfo{},
			Metadata:      make(map[string]string),
		},
		{
			Name:          "aws-ebs-csi-driver",
			Type:          "csi",
			Version:       "v1.15.0",
			LatestVersion: "v1.20.0",
			Outdated:      true,
			Vulnerable:    true,
			RiskLevel:     "medium",
			CVEs:          []CVEInfo{},
			Metadata:      make(map[string]string),
		},
	}

	for _, addon := range simulatedAddons {
		if addon.Outdated {
			findings = append(findings, VulnerabilityFinding{
				ID:          "vuln-005",
				Type:        "addon-version",
				Severity:    addon.RiskLevel,
				Title:       "Outdated Addon Version",
				Description: fmt.Sprintf("Addon %s version %s is outdated.", addon.Name, addon.Version),
				Resource:    fmt.Sprintf("addon/%s", addon.Name),
				Namespace:   "",
				RiskScore:   vs.getRiskScore(addon.RiskLevel),
				Remediation: fmt.Sprintf("Upgrade %s to version %s.", addon.Name, addon.LatestVersion),
				Timestamp:   time.Now(),
				Metadata: map[string]string{
					"addon_name":      addon.Name,
					"addon_type":      addon.Type,
					"current_version": addon.Version,
					"latest_version":  addon.LatestVersion,
				},
			})
		}

		// Simulate CVE detection
		cves := vs.detectAddonCVEs(addon)
		addon.CVEs = cves
		if len(cves) > 0 {
			addon.Vulnerable = true
		}

		addons = append(addons, addon)
	}

	return addons, findings, nil
}

// Helper methods for vulnerability detection
func (vs *VulnerabilityScanner) isOutdatedKubernetesVersion(version string) bool {
	// This is a simplified check - in reality, you'd compare against known versions
	outdatedPatterns := []string{
		"v1.20", "v1.21", "v1.22", "v1.23", "v1.24",
	}

	for _, pattern := range outdatedPatterns {
		if strings.Contains(version, pattern) {
			return true
		}
	}
	return false
}

func (vs *VulnerabilityScanner) isOutdatedKubeletVersion(version string) bool {
	// This is a simplified check - in reality, you'd compare against known versions
	outdatedPatterns := []string{
		"v1.20", "v1.21", "v1.22", "v1.23", "v1.24",
	}

	for _, pattern := range outdatedPatterns {
		if strings.Contains(version, pattern) {
			return true
		}
	}
	return false
}

func (vs *VulnerabilityScanner) isOutdatedRuntime(version string) bool {
	// This is a simplified check - in reality, you'd compare against known versions
	outdatedPatterns := []string{
		"containerd://1.4", "containerd://1.5", "containerd://1.6",
		"docker://19.03", "docker://20.10.0",
	}

	for _, pattern := range outdatedPatterns {
		if strings.Contains(version, pattern) {
			return true
		}
	}
	return false
}

func (vs *VulnerabilityScanner) getRiskScore(riskLevel string) float64 {
	switch strings.ToLower(riskLevel) {
	case "critical":
		return 10.0
	case "high":
		return 8.0
	case "medium":
		return 6.0
	case "low":
		return 4.0
	default:
		return 5.0
	}
}

func (vs *VulnerabilityScanner) detectNodeCVEs(nodeInfo NodeInfo) []CVEInfo {
	// Simulate CVE detection for nodes
	var cves []CVEInfo

	// Simulate some CVEs
	if strings.Contains(nodeInfo.KubeletVersion, "v1.25") {
		cves = append(cves, CVEInfo{
			ID:               "CVE-2023-1234",
			Description:      "Kubelet vulnerability in version 1.25.x",
			Severity:         "high",
			Score:            8.5,
			Vector:           "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			Published:        time.Now().AddDate(0, -6, 0),
			Modified:         time.Now().AddDate(0, -3, 0),
			AffectedVersions: []string{"v1.25.0", "v1.25.1", "v1.25.2"},
			FixedVersions:    []string{"v1.25.3", "v1.26.0"},
			References:       []string{"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-1234"},
			Metadata:         make(map[string]string),
		})
	}

	return cves
}

func (vs *VulnerabilityScanner) detectComponentCVEs(component ComponentInfo) []CVEInfo {
	// Simulate CVE detection for components
	var cves []CVEInfo

	// Simulate some CVEs
	if strings.Contains(component.Version, "v1.25") {
		cves = append(cves, CVEInfo{
			ID:               "CVE-2023-5678",
			Description:      fmt.Sprintf("%s vulnerability in version 1.25.x", component.Name),
			Severity:         "critical",
			Score:            9.5,
			Vector:           "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			Published:        time.Now().AddDate(0, -4, 0),
			Modified:         time.Now().AddDate(0, -2, 0),
			AffectedVersions: []string{"v1.25.0", "v1.25.1"},
			FixedVersions:    []string{"v1.25.2", "v1.26.0"},
			References:       []string{"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-5678"},
			Metadata:         make(map[string]string),
		})
	}

	return cves
}

func (vs *VulnerabilityScanner) detectAddonCVEs(addon AddonInfo) []CVEInfo {
	// Simulate CVE detection for addons
	var cves []CVEInfo

	// Simulate some CVEs
	if strings.Contains(addon.Version, "v1.2") {
		cves = append(cves, CVEInfo{
			ID:               "CVE-2023-9012",
			Description:      fmt.Sprintf("%s vulnerability in version 1.2.x", addon.Name),
			Severity:         "medium",
			Score:            6.5,
			Vector:           "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N",
			Published:        time.Now().AddDate(0, -2, 0),
			Modified:         time.Now().AddDate(0, -1, 0),
			AffectedVersions: []string{"v1.2.0", "v1.2.1"},
			FixedVersions:    []string{"v1.2.2", "v1.3.0"},
			References:       []string{"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-9012"},
			Metadata:         make(map[string]string),
		})
	}

	return cves
}
