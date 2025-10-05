package supply_chain

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"kubeshadow/pkg/logger"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// SupplyChainFinding represents a supply chain security finding
type SupplyChainFinding struct {
	ImageName       string                 `json:"imageName"`
	ImageDigest     string                 `json:"imageDigest"`
	Namespace       string                 `json:"namespace"`
	WorkloadName    string                 `json:"workloadName"`
	WorkloadType    string                 `json:"workloadType"`
	Severity        string                 `json:"severity"`
	RiskScore       float64                `json:"riskScore"`
	Vulnerabilities []VulnerabilityInfo    `json:"vulnerabilities"`
	RegistryInfo    RegistryInfo           `json:"registryInfo"`
	ProvenanceInfo  ProvenanceInfo         `json:"provenanceInfo"`
	CIInfo          CIInfo                 `json:"ciInfo"`
	Remediation     SupplyChainRemediation `json:"remediation"`
	UsageCount      int                    `json:"usageCount"`
	CrossNamespace  bool                   `json:"crossNamespace"`
}

// VulnerabilityInfo represents CVE information
type VulnerabilityInfo struct {
	CVEID          string  `json:"cveId"`
	Severity       string  `json:"severity"`
	CVSS           float64 `json:"cvss"`
	Description    string  `json:"description"`
	PackageName    string  `json:"packageName"`
	PackageVersion string  `json:"packageVersion"`
	FixedVersion   string  `json:"fixedVersion"`
}

// RegistryInfo contains registry security information
type RegistryInfo struct {
	RegistryURL     string `json:"registryUrl"`
	IsPublic        bool   `json:"isPublic"`
	IsMutable       bool   `json:"isMutable"`
	RequiresAuth    bool   `json:"requiresAuth"`
	AnonymousPush   bool   `json:"anonymousPush"`
	ImagePullSecret string `json:"imagePullSecret"`
}

// ProvenanceInfo contains image provenance information
type ProvenanceInfo struct {
	HasSignature   bool   `json:"hasSignature"`
	HasAttestation bool   `json:"hasAttestation"`
	SignerIdentity string `json:"signerIdentity"`
	BuildTimestamp string `json:"buildTimestamp"`
	SourceRepo     string `json:"sourceRepo"`
	BuildSystem    string `json:"buildSystem"`
}

// CIInfo contains CI/CD pipeline information
type CIInfo struct {
	HasCI         bool   `json:"hasCI"`
	CISystem      string `json:"ciSystem"`
	HasSBOM       bool   `json:"hasSBOM"`
	HasScanning   bool   `json:"hasScanning"`
	ScanFrequency string `json:"scanFrequency"`
	LastScanDate  string `json:"lastScanDate"`
}

// SupplyChainRemediation provides fix suggestions
type SupplyChainRemediation struct {
	Description     string   `json:"description"`
	ImageHardening  []string `json:"imageHardening"`
	CIHardening     []string `json:"ciHardening"`
	GitOpsHardening []string `json:"gitOpsHardening"`
	KubectlApply    string   `json:"kubectlApply"`
}

// SupplyChainScanner scans for supply chain vulnerabilities
type SupplyChainScanner struct {
	clientset *kubernetes.Clientset
	ctx       context.Context
	trivyURL  string
}

// NewSupplyChainScanner creates a new scanner instance
func NewSupplyChainScanner(ctx context.Context, kubeconfig, trivyURL string) (*SupplyChainScanner, error) {
	config, err := getKubeConfig(kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("failed to get kubeconfig: %v", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create clientset: %v", err)
	}

	return &SupplyChainScanner{
		clientset: clientset,
		ctx:       ctx,
		trivyURL:  trivyURL,
	}, nil
}

// ScanSupplyChain performs comprehensive supply chain security scanning
func (s *SupplyChainScanner) ScanSupplyChain() ([]SupplyChainFinding, error) {
	var findings []SupplyChainFinding

	// Get all images from the cluster
	images, err := s.getAllImages()
	if err != nil {
		return nil, fmt.Errorf("failed to get images: %v", err)
	}

	// Analyze each image
	for _, image := range images {
		finding, err := s.analyzeImage(image)
		if err != nil {
			logger.Warn("Failed to analyze image %s: %v", image, err)
			continue
		}
		if finding != nil {
			findings = append(findings, *finding)
		}
	}

	return findings, nil
}

// getAllImages extracts all container images from the cluster
func (s *SupplyChainScanner) getAllImages() ([]string, error) {
	var images []string
	imageMap := make(map[string]bool)

	// Get all pods
	pods, err := s.clientset.CoreV1().Pods("").List(s.ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	for _, pod := range pods.Items {
		for _, container := range pod.Spec.Containers {
			if !imageMap[container.Image] {
				images = append(images, container.Image)
				imageMap[container.Image] = true
			}
		}
		for _, initContainer := range pod.Spec.InitContainers {
			if !imageMap[initContainer.Image] {
				images = append(images, initContainer.Image)
				imageMap[initContainer.Image] = true
			}
		}
	}

	return images, nil
}

// analyzeImage analyzes a single container image for supply chain vulnerabilities
func (s *SupplyChainScanner) analyzeImage(imageName string) (*SupplyChainFinding, error) {
	// Parse image name
	registryInfo := s.parseRegistryInfo(imageName)

	// Check for risky patterns
	riskScore := 0.0
	var vulnerabilities []VulnerabilityInfo

	// Check for latest tag
	if strings.HasSuffix(imageName, ":latest") || !strings.Contains(imageName, ":") {
		riskScore += 5.0
	}

	// Check for mutable registry
	if s.isMutableRegistry(registryInfo.RegistryURL) {
		riskScore += 7.0
		registryInfo.IsMutable = true
	}

	// Check for public registry
	if s.isPublicRegistry(registryInfo.RegistryURL) {
		riskScore += 3.0
		registryInfo.IsPublic = true
	}

	// Scan for vulnerabilities using Trivy
	if s.trivyURL != "" {
		vulns, err := s.scanWithTrivy(imageName)
		if err != nil {
			logger.Warn("Trivy scan failed for %s: %v", imageName, err)
		} else {
			vulnerabilities = vulns
			for _, vuln := range vulns {
				riskScore += vuln.CVSS
			}
		}
	}

	// Check provenance
	provenanceInfo := s.checkProvenance(imageName)
	if !provenanceInfo.HasSignature {
		riskScore += 4.0
	}

	// Check CI information
	ciInfo := s.checkCIInfo(imageName)
	if !ciInfo.HasScanning {
		riskScore += 2.0
	}

	// Calculate usage count
	usageCount := s.getImageUsageCount(imageName)
	if usageCount > 5 {
		riskScore += 2.0
	}

	// Determine severity
	severity := "LOW"
	if riskScore >= 15.0 {
		severity = "CRITICAL"
	} else if riskScore >= 10.0 {
		severity = "HIGH"
	} else if riskScore >= 5.0 {
		severity = "MEDIUM"
	}

	// Generate remediation
	remediation := s.generateRemediation(imageName, registryInfo, provenanceInfo, ciInfo)

	return &SupplyChainFinding{
		ImageName:       imageName,
		ImageDigest:     s.getImageDigest(imageName),
		Namespace:       "multiple", // Will be updated with actual usage
		WorkloadName:    "multiple", // Will be updated with actual usage
		WorkloadType:    "multiple", // Will be updated with actual usage
		Severity:        severity,
		RiskScore:       riskScore,
		Vulnerabilities: vulnerabilities,
		RegistryInfo:    registryInfo,
		ProvenanceInfo:  provenanceInfo,
		CIInfo:          ciInfo,
		Remediation:     remediation,
		UsageCount:      usageCount,
		CrossNamespace:  usageCount > 1,
	}, nil
}

// parseRegistryInfo extracts registry information from image name
func (s *SupplyChainScanner) parseRegistryInfo(imageName string) RegistryInfo {
	parts := strings.Split(imageName, "/")
	registryURL := ""

	if len(parts) > 1 {
		// Check if first part contains a registry
		if strings.Contains(parts[0], ".") || strings.Contains(parts[0], ":") {
			registryURL = parts[0]
		}
	}

	return RegistryInfo{
		RegistryURL:  registryURL,
		IsPublic:     s.isPublicRegistry(registryURL),
		IsMutable:    s.isMutableRegistry(registryURL),
		RequiresAuth: s.requiresAuth(registryURL),
	}
}

// isPublicRegistry checks if registry is public
func (s *SupplyChainScanner) isPublicRegistry(registryURL string) bool {
	publicRegistries := []string{
		"docker.io",
		"gcr.io",
		"quay.io",
		"registry.hub.docker.com",
		"",
	}

	for _, public := range publicRegistries {
		if registryURL == public {
			return true
		}
	}
	return false
}

// isMutableRegistry checks if registry allows mutable tags
func (s *SupplyChainScanner) isMutableRegistry(_ string) bool {
	// Most registries allow mutable tags by default
	// This is a simplified check
	return true
}

// requiresAuth checks if registry requires authentication
func (s *SupplyChainScanner) requiresAuth(registryURL string) bool {
	// Simplified check - would need actual registry API calls
	return registryURL != "" && !s.isPublicRegistry(registryURL)
}

// scanWithTrivy performs vulnerability scanning using Trivy
func (s *SupplyChainScanner) scanWithTrivy(_ string) ([]VulnerabilityInfo, error) {
	// This would integrate with Trivy API
	// For now, return mock data
	return []VulnerabilityInfo{
		{
			CVEID:          "CVE-2023-1234",
			Severity:       "HIGH",
			CVSS:           7.5,
			Description:    "Example vulnerability",
			PackageName:    "openssl",
			PackageVersion: "1.1.1",
			FixedVersion:   "1.1.1t",
		},
	}, nil
}

// checkProvenance checks image provenance and signatures
func (s *SupplyChainScanner) checkProvenance(_ string) ProvenanceInfo {
	// This would check for cosign signatures and attestations
	// For now, return mock data
	return ProvenanceInfo{
		HasSignature:   false,
		HasAttestation: false,
		SignerIdentity: "",
		BuildTimestamp: "",
		SourceRepo:     "",
		BuildSystem:    "",
	}
}

// checkCIInfo checks CI/CD pipeline information
func (s *SupplyChainScanner) checkCIInfo(_ string) CIInfo {
	// This would analyze CI/CD metadata
	// For now, return mock data
	return CIInfo{
		HasCI:         false,
		CISystem:      "",
		HasSBOM:       false,
		HasScanning:   false,
		ScanFrequency: "",
		LastScanDate:  "",
	}
}

// getImageUsageCount counts how many times an image is used
func (s *SupplyChainScanner) getImageUsageCount(imageName string) int {
	count := 0

	pods, err := s.clientset.CoreV1().Pods("").List(s.ctx, metav1.ListOptions{})
	if err != nil {
		return 0
	}

	for _, pod := range pods.Items {
		for _, container := range pod.Spec.Containers {
			if container.Image == imageName {
				count++
			}
		}
		for _, initContainer := range pod.Spec.InitContainers {
			if initContainer.Image == imageName {
				count++
			}
		}
	}

	return count
}

// getImageDigest gets the digest of an image
func (s *SupplyChainScanner) getImageDigest(_ string) string {
	// This would query the registry for the actual digest
	// For now, return a placeholder
	return "sha256:placeholder"
}

// generateRemediation generates remediation suggestions
func (s *SupplyChainScanner) generateRemediation(_ string, _ RegistryInfo, _ ProvenanceInfo, _ CIInfo) SupplyChainRemediation {
	var imageHardening []string
	var ciHardening []string
	var gitOpsHardening []string

	// Image hardening suggestions
	imageHardening = append(imageHardening, "Use specific image tags instead of :latest")
	imageHardening = append(imageHardening, "Sign images with cosign")
	imageHardening = append(imageHardening, "Use distroless or minimal base images")
	imageHardening = append(imageHardening, "Regularly update base images")

	// CI hardening suggestions
	ciHardening = append(ciHardening, "Implement automated vulnerability scanning")
	ciHardening = append(ciHardening, "Generate SBOM for all images")
	ciHardening = append(ciHardening, "Use multi-stage builds")
	ciHardening = append(ciHardening, "Implement image signing in CI/CD")

	// GitOps hardening suggestions
	gitOpsHardening = append(gitOpsHardening, "Use image digest instead of tags")
	gitOpsHardening = append(gitOpsHardening, "Implement image policy enforcement")
	gitOpsHardening = append(gitOpsHardening, "Use admission controllers for image validation")
	gitOpsHardening = append(gitOpsHardening, "Implement automated image updates")

	// Generate kubectl apply command
	kubectlApply := `# Apply image policy enforcement
kubectl apply -f - <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: image-policy
  namespace: gatekeeper-system
data:
  policy.rego: |
    package imagepolicy
    
    deny[msg] {
        input.request.object.spec.containers[_].image
        not startswith(input.request.object.spec.containers[_].image, "sha256:")
        msg := "Images must use digest instead of tags"
    }
EOF`

	return SupplyChainRemediation{
		Description:     "Implement comprehensive supply chain security measures",
		ImageHardening:  imageHardening,
		CIHardening:     ciHardening,
		GitOpsHardening: gitOpsHardening,
		KubectlApply:    kubectlApply,
	}
}

// getKubeConfig creates a Kubernetes config
func getKubeConfig(kubeconfig string) (*rest.Config, error) {
	if kubeconfig != "" {
		return clientcmd.BuildConfigFromFlags("", kubeconfig)
	}
	return rest.InClusterConfig()
}

// SaveFindingsToFile saves findings to supplychain_report.json
func (s *SupplyChainScanner) SaveFindingsToFile(findings []SupplyChainFinding, outputPath string) error {
	// Create output directory if it doesn't exist
	dir := filepath.Dir(outputPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %v", err)
	}

	// Create comprehensive report
	report := SupplyChainReport{
		ScanMetadata: ScanMetadata{
			ScanID:      fmt.Sprintf("kubeshadow-supplychain-%d", time.Now().Unix()),
			Timestamp:   time.Now(),
			Version:     "1.0.0",
			Scanner:     "KubeShadow K02",
			TotalImages: len(findings),
		},
		Summary:  s.generateSummary(findings),
		Findings: findings,
	}

	// Marshal to JSON
	jsonData, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %v", err)
	}

	// Write to file
	if err := os.WriteFile(outputPath, jsonData, 0644); err != nil {
		return fmt.Errorf("failed to write JSON file: %v", err)
	}

	logger.Info("✅ Supply chain findings saved to: %s", outputPath)
	return nil
}

// SupplyChainReport represents the complete supply chain scan report
type SupplyChainReport struct {
	ScanMetadata ScanMetadata         `json:"scanMetadata"`
	Summary      SupplyChainSummary   `json:"summary"`
	Findings     []SupplyChainFinding `json:"findings"`
}

// ScanMetadata contains information about the scan
type ScanMetadata struct {
	ScanID      string    `json:"scanId"`
	Timestamp   time.Time `json:"timestamp"`
	Version     string    `json:"version"`
	Scanner     string    `json:"scanner"`
	TotalImages int       `json:"totalImages"`
}

// SupplyChainSummary provides high-level statistics
type SupplyChainSummary struct {
	TotalImages          int               `json:"totalImages"`
	VulnerableImages     int               `json:"vulnerableImages"`
	TotalVulnerabilities int               `json:"totalVulnerabilities"`
	AverageRiskScore     float64           `json:"averageRiskScore"`
	MaxRiskScore         float64           `json:"maxRiskScore"`
	SeverityBreakdown    SeverityBreakdown `json:"severityBreakdown"`
	RegistryBreakdown    RegistryBreakdown `json:"registryBreakdown"`
}

// SeverityBreakdown shows count by severity
type SeverityBreakdown struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
}

// RegistryBreakdown shows registry distribution
type RegistryBreakdown struct {
	PublicRegistries  int `json:"publicRegistries"`
	PrivateRegistries int `json:"privateRegistries"`
	MutableRegistries int `json:"mutableRegistries"`
}

// generateSummary creates a summary of the findings
func (s *SupplyChainScanner) generateSummary(findings []SupplyChainFinding) SupplyChainSummary {
	totalImages := len(findings)
	vulnerableImages := 0
	totalVulnerabilities := 0
	totalRiskScore := 0.0
	maxRiskScore := 0.0

	severityBreakdown := SeverityBreakdown{}
	registryBreakdown := RegistryBreakdown{}

	for _, finding := range findings {
		if len(finding.Vulnerabilities) > 0 {
			vulnerableImages++
		}

		totalVulnerabilities += len(finding.Vulnerabilities)
		totalRiskScore += finding.RiskScore

		if finding.RiskScore > maxRiskScore {
			maxRiskScore = finding.RiskScore
		}

		// Count by severity
		switch finding.Severity {
		case "CRITICAL":
			severityBreakdown.Critical++
		case "HIGH":
			severityBreakdown.High++
		case "MEDIUM":
			severityBreakdown.Medium++
		case "LOW":
			severityBreakdown.Low++
		}

		// Count by registry type
		if finding.RegistryInfo.IsPublic {
			registryBreakdown.PublicRegistries++
		} else {
			registryBreakdown.PrivateRegistries++
		}

		if finding.RegistryInfo.IsMutable {
			registryBreakdown.MutableRegistries++
		}
	}

	averageRiskScore := 0.0
	if totalImages > 0 {
		averageRiskScore = totalRiskScore / float64(totalImages)
	}

	return SupplyChainSummary{
		TotalImages:          totalImages,
		VulnerableImages:     vulnerableImages,
		TotalVulnerabilities: totalVulnerabilities,
		AverageRiskScore:     averageRiskScore,
		MaxRiskScore:         maxRiskScore,
		SeverityBreakdown:    severityBreakdown,
		RegistryBreakdown:    registryBreakdown,
	}
}
