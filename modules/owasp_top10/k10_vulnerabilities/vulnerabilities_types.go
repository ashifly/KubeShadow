package k10_vulnerabilities

import (
	"context"
	"time"

	"k8s.io/client-go/kubernetes"
)

// VulnerabilityFinding represents a vulnerability security finding
type VulnerabilityFinding struct {
	ID          string            `json:"id"`
	Type        string            `json:"type"`
	Severity    string            `json:"severity"`
	Title       string            `json:"title"`
	Description string            `json:"description"`
	Resource    string            `json:"resource"`
	Namespace   string            `json:"namespace"`
	RiskScore   float64           `json:"riskScore"`
	Remediation string            `json:"remediation"`
	Timestamp   time.Time         `json:"timestamp"`
	Metadata    map[string]string `json:"metadata"`
}

// VulnerabilitySummary represents summary statistics for vulnerability findings
type VulnerabilitySummary struct {
	TotalFindings      int     `json:"totalFindings"`
	CriticalCount      int     `json:"criticalCount"`
	HighCount          int     `json:"highCount"`
	MediumCount        int     `json:"mediumCount"`
	LowCount           int     `json:"lowCount"`
	VulnerabilityScore float64 `json:"vulnerabilityScore"`
	CVECount           int     `json:"cveCount"`
	CriticalCVEs       int     `json:"criticalCVEs"`
	HighCVEs           int     `json:"highCVEs"`
	OutdatedComponents int     `json:"outdatedComponents"`
	KubernetesVersion  string  `json:"kubernetesVersion"`
	KubeletVersion     string  `json:"kubeletVersion"`
	APIServerVersion   string  `json:"apiServerVersion"`
	CNIVersion         string  `json:"cniVersion"`
	CSIVersion         string  `json:"csiVersion"`
	RuntimeVersion     string  `json:"runtimeVersion"`
	IngressVersion     string  `json:"ingressVersion"`
}

// VulnerabilityScanner represents the vulnerability scanner
type VulnerabilityScanner struct {
	client    kubernetes.Interface
	namespace string
	ctx       context.Context
	labMode   bool
}

// ComponentInfo represents information about a Kubernetes component
type ComponentInfo struct {
	Name          string            `json:"name"`
	Type          string            `json:"type"`
	Version       string            `json:"version"`
	LatestVersion string            `json:"latestVersion"`
	Outdated      bool              `json:"outdated"`
	Vulnerable    bool              `json:"vulnerable"`
	RiskLevel     string            `json:"riskLevel"`
	CVEs          []CVEInfo         `json:"cves"`
	Metadata      map[string]string `json:"metadata"`
}

// CVEInfo represents information about a CVE
type CVEInfo struct {
	ID               string            `json:"id"`
	Description      string            `json:"description"`
	Severity         string            `json:"severity"`
	Score            float64           `json:"score"`
	Vector           string            `json:"vector"`
	Published        time.Time         `json:"published"`
	Modified         time.Time         `json:"modified"`
	AffectedVersions []string          `json:"affectedVersions"`
	FixedVersions    []string          `json:"fixedVersions"`
	References       []string          `json:"references"`
	Metadata         map[string]string `json:"metadata"`
}

// KubernetesVersion represents Kubernetes version information
type KubernetesVersion struct {
	Major      string `json:"major"`
	Minor      string `json:"minor"`
	GitVersion string `json:"gitVersion"`
	GitCommit  string `json:"gitCommit"`
	BuildDate  string `json:"buildDate"`
	GoVersion  string `json:"goVersion"`
	Compiler   string `json:"compiler"`
	Platform   string `json:"platform"`
}

// NodeInfo represents node information
type NodeInfo struct {
	Name           string            `json:"name"`
	Version        string            `json:"version"`
	OS             string            `json:"os"`
	Architecture   string            `json:"architecture"`
	Runtime        string            `json:"runtime"`
	CNI            string            `json:"cni"`
	CSI            string            `json:"csi"`
	KubeletVersion string            `json:"kubeletVersion"`
	Vulnerable     bool              `json:"vulnerable"`
	CVEs           []CVEInfo         `json:"cves"`
	Metadata       map[string]string `json:"metadata"`
}

// AddonInfo represents addon information
type AddonInfo struct {
	Name          string            `json:"name"`
	Type          string            `json:"type"`
	Version       string            `json:"version"`
	LatestVersion string            `json:"latestVersion"`
	Outdated      bool              `json:"outdated"`
	Vulnerable    bool              `json:"vulnerable"`
	RiskLevel     string            `json:"riskLevel"`
	CVEs          []CVEInfo         `json:"cves"`
	Metadata      map[string]string `json:"metadata"`
}

// UpgradePlan represents an upgrade plan
type UpgradePlan struct {
	Component      string            `json:"component"`
	CurrentVersion string            `json:"currentVersion"`
	TargetVersion  string            `json:"targetVersion"`
	Steps          []UpgradeStep     `json:"steps"`
	PreChecks      []PreCheck        `json:"preChecks"`
	RiskLevel      string            `json:"riskLevel"`
	Metadata       map[string]string `json:"metadata"`
}

// UpgradeStep represents an upgrade step
type UpgradeStep struct {
	Step        int               `json:"step"`
	Description string            `json:"description"`
	Command     string            `json:"command"`
	RiskLevel   string            `json:"riskLevel"`
	Metadata    map[string]string `json:"metadata"`
}

// PreCheck represents a pre-upgrade check
type PreCheck struct {
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Command     string            `json:"command"`
	Required    bool              `json:"required"`
	Metadata    map[string]string `json:"metadata"`
}

// VulnerabilityReport represents the complete vulnerability report
type VulnerabilityReport struct {
	Findings          []VulnerabilityFinding `json:"findings"`
	Summary           VulnerabilitySummary   `json:"summary"`
	Components        []ComponentInfo        `json:"components"`
	Nodes             []NodeInfo             `json:"nodes"`
	Addons            []AddonInfo            `json:"addons"`
	KubernetesVersion KubernetesVersion      `json:"kubernetesVersion"`
	UpgradePlans      []UpgradePlan          `json:"upgradePlans"`
	PreflightTests    []PreCheck             `json:"preflightTests"`
	Recommendations   []string               `json:"recommendations"`
	GeneratedAt       time.Time              `json:"generatedAt"`
}
