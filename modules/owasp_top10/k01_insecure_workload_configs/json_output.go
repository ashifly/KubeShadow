package workload_config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"kubeshadow/pkg/logger"
)

// WorkloadScanReport represents the complete scan report
type WorkloadScanReport struct {
	ScanMetadata ScanMetadata      `json:"scanMetadata"`
	Summary      ScanSummary       `json:"summary"`
	Findings     []WorkloadFinding `json:"findings"`
}

// ScanMetadata contains information about the scan
type ScanMetadata struct {
	ScanID      string    `json:"scanId"`
	Timestamp   time.Time `json:"timestamp"`
	Version     string    `json:"version"`
	Scanner     string    `json:"scanner"`
	KubeVersion string    `json:"kubeVersion"`
	ClusterName string    `json:"clusterName"`
	Namespaces  []string  `json:"namespaces"`
}

// ScanSummary provides high-level statistics
type ScanSummary struct {
	TotalWorkloads       int               `json:"totalWorkloads"`
	VulnerableWorkloads  int               `json:"vulnerableWorkloads"`
	TotalVulnerabilities int               `json:"totalVulnerabilities"`
	AverageRiskScore     float64           `json:"averageRiskScore"`
	MaxRiskScore         float64           `json:"maxRiskScore"`
	SeverityBreakdown    SeverityBreakdown `json:"severityBreakdown"`
	RiskDistribution     RiskDistribution  `json:"riskDistribution"`
}

// SeverityBreakdown shows count by severity
type SeverityBreakdown struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
}

// RiskDistribution shows risk score distribution
type RiskDistribution struct {
	Critical int `json:"critical"` // >= 9.0
	High     int `json:"high"`     // 7.0 - 8.9
	Medium   int `json:"medium"`   // 4.0 - 6.9
	Low      int `json:"low"`      // < 4.0
}

// SaveFindingsToJSON saves findings to JSON format
func (w *WorkloadConfigScanner) SaveFindingsToJSON(findings []WorkloadFinding, outputPath string) error {
	// Create output directory if it doesn't exist
	dir := filepath.Dir(outputPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %v", err)
	}

	// Generate scan metadata
	metadata := ScanMetadata{
		ScanID:      fmt.Sprintf("kubeshadow-workload-%d", time.Now().Unix()),
		Timestamp:   time.Now(),
		Version:     "1.0.0",
		Scanner:     "KubeShadow K01",
		KubeVersion: "unknown", // Would be populated from cluster info
		ClusterName: "unknown", // Would be populated from cluster info
		Namespaces:  w.getUniqueNamespaces(findings),
	}

	// Generate summary
	summary := w.generateSummary(findings)

	// Create report
	report := WorkloadScanReport{
		ScanMetadata: metadata,
		Summary:      summary,
		Findings:     findings,
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

	logger.Info("✅ Workload security findings saved to JSON: %s", outputPath)
	return nil
}

// getUniqueNamespaces extracts unique namespaces from findings
func (w *WorkloadConfigScanner) getUniqueNamespaces(findings []WorkloadFinding) []string {
	namespaceMap := make(map[string]bool)
	for _, finding := range findings {
		namespaceMap[finding.Namespace] = true
	}

	var namespaces []string
	for ns := range namespaceMap {
		namespaces = append(namespaces, ns)
	}
	return namespaces
}

// generateSummary creates a summary of the findings
func (w *WorkloadConfigScanner) generateSummary(findings []WorkloadFinding) ScanSummary {
	totalWorkloads := len(findings)
	vulnerableWorkloads := 0
	totalVulnerabilities := 0
	totalRiskScore := 0.0
	maxRiskScore := 0.0

	severityBreakdown := SeverityBreakdown{}
	riskDistribution := RiskDistribution{}

	for _, finding := range findings {
		if len(finding.Vulnerabilities) > 0 {
			vulnerableWorkloads++
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

		// Count by risk score
		if finding.RiskScore >= 9.0 {
			riskDistribution.Critical++
		} else if finding.RiskScore >= 7.0 {
			riskDistribution.High++
		} else if finding.RiskScore >= 4.0 {
			riskDistribution.Medium++
		} else {
			riskDistribution.Low++
		}
	}

	averageRiskScore := 0.0
	if totalWorkloads > 0 {
		averageRiskScore = totalRiskScore / float64(totalWorkloads)
	}

	return ScanSummary{
		TotalWorkloads:       totalWorkloads,
		VulnerableWorkloads:  vulnerableWorkloads,
		TotalVulnerabilities: totalVulnerabilities,
		AverageRiskScore:     averageRiskScore,
		MaxRiskScore:         maxRiskScore,
		SeverityBreakdown:    severityBreakdown,
		RiskDistribution:     riskDistribution,
	}
}

// LoadFindingsFromJSON loads findings from JSON file
func LoadFindingsFromJSON(filePath string) (*WorkloadScanReport, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read JSON file: %v", err)
	}

	var report WorkloadScanReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON: %v", err)
	}

	return &report, nil
}

// ExportToCSV exports findings to CSV format
func (w *WorkloadConfigScanner) ExportToCSV(findings []WorkloadFinding, outputPath string) error {
	// Create output directory if it doesn't exist
	dir := filepath.Dir(outputPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %v", err)
	}

	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create CSV file: %v", err)
	}
	defer file.Close()

	// Write CSV header
	file.WriteString("WorkloadName,WorkloadType,Namespace,Severity,RiskScore,HostExposure,ServiceAccount,NamespaceSensitive,VulnerabilityCount\n")

	// Write findings
	for _, finding := range findings {
		file.WriteString(fmt.Sprintf("%s,%s,%s,%s,%.2f,%t,%s,%t,%d\n",
			finding.WorkloadName,
			finding.WorkloadType,
			finding.Namespace,
			finding.Severity,
			finding.RiskScore,
			finding.HostExposure,
			finding.ServiceAccount,
			finding.NamespaceSensitive,
			len(finding.Vulnerabilities),
		))
	}

	logger.Info("✅ Workload security findings exported to CSV: %s", outputPath)
	return nil
}

// GenerateOPAPolicy generates a complete OPA policy for all findings
func (w *WorkloadConfigScanner) GenerateOPAPolicy(findings []WorkloadFinding, outputPath string) error {
	// Create output directory if it doesn't exist
	dir := filepath.Dir(outputPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %v", err)
	}

	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create OPA policy file: %v", err)
	}
	defer file.Close()

	// Write OPA policy header
	file.WriteString("package kubernetes.admission\n\n")
	file.WriteString("# KubeShadow K01 - Insecure Workload Configurations Policy\n")
	file.WriteString("# Generated automatically based on scan findings\n\n")

	// Write policy rules
	file.WriteString("# Deny privileged containers\n")
	file.WriteString("deny[msg] {\n")
	file.WriteString("    input.request.kind.kind == \"Pod\"\n")
	file.WriteString("    input.request.operation == \"CREATE\"\n")
	file.WriteString("    input.request.object.spec.containers[_].securityContext.privileged == true\n")
	file.WriteString("    msg := \"Privileged containers are not allowed\"\n")
	file.WriteString("}\n\n")

	file.WriteString("# Deny root user\n")
	file.WriteString("deny[msg] {\n")
	file.WriteString("    input.request.kind.kind == \"Pod\"\n")
	file.WriteString("    input.request.operation == \"CREATE\"\n")
	file.WriteString("    input.request.object.spec.securityContext.runAsUser == 0\n")
	file.WriteString("    msg := \"Running as root user is not allowed\"\n")
	file.WriteString("}\n\n")

	file.WriteString("# Deny privilege escalation\n")
	file.WriteString("deny[msg] {\n")
	file.WriteString("    input.request.kind.kind == \"Pod\"\n")
	file.WriteString("    input.request.operation == \"CREATE\"\n")
	file.WriteString("    input.request.object.spec.containers[_].securityContext.allowPrivilegeEscalation == true\n")
	file.WriteString("    msg := \"Privilege escalation is not allowed\"\n")
	file.WriteString("}\n\n")

	file.WriteString("# Deny host network\n")
	file.WriteString("deny[msg] {\n")
	file.WriteString("    input.request.kind.kind == \"Pod\"\n")
	file.WriteString("    input.request.operation == \"CREATE\"\n")
	file.WriteString("    input.request.object.spec.hostNetwork == true\n")
	file.WriteString("    msg := \"Host network is not allowed\"\n")
	file.WriteString("}\n\n")

	file.WriteString("# Deny host path volumes\n")
	file.WriteString("deny[msg] {\n")
	file.WriteString("    input.request.kind.kind == \"Pod\"\n")
	file.WriteString("    input.request.operation == \"CREATE\"\n")
	file.WriteString("    input.request.object.spec.volumes[_].hostPath\n")
	file.WriteString("    msg := \"Host path volumes are not allowed\"\n")
	file.WriteString("}\n\n")

	logger.Info("✅ OPA policy generated: %s", outputPath)
	return nil
}
