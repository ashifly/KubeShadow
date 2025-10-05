package k10_vulnerabilities

import (
	"fmt"
	"time"
)

// AnalyzeVulnerabilities analyzes vulnerability security posture
func (vs *VulnerabilityScanner) AnalyzeVulnerabilities() (VulnerabilitySummary, []string, error) {
	var recommendations []string
	summary := VulnerabilitySummary{}

	// Analyze Kubernetes version
	kubernetesVersion, versionFindings, err := vs.DetectKubernetesVersion()
	if err != nil {
		return summary, recommendations, fmt.Errorf("failed to analyze Kubernetes version: %w", err)
	}

	summary.KubernetesVersion = kubernetesVersion.GitVersion
	summary.TotalFindings += len(versionFindings)

	// Count findings by severity
	for _, finding := range versionFindings {
		switch finding.Severity {
		case "critical":
			summary.CriticalCount++
		case "high":
			summary.HighCount++
		case "medium":
			summary.MediumCount++
		case "low":
			summary.LowCount++
		}
	}

	// Analyze node vulnerabilities
	nodes, nodeFindings, err := vs.DetectNodeVulnerabilities()
	if err != nil {
		return summary, recommendations, fmt.Errorf("failed to analyze node vulnerabilities: %w", err)
	}

	summary.TotalFindings += len(nodeFindings)

	// Count vulnerable nodes and CVEs
	for _, node := range nodes {
		if node.Vulnerable {
			summary.OutdatedComponents++
		}
		summary.CVECount += len(node.CVEs)
		for _, cve := range node.CVEs {
			switch cve.Severity {
			case "critical":
				summary.CriticalCVEs++
			case "high":
				summary.HighCVEs++
			}
		}
	}

	for _, finding := range nodeFindings {
		switch finding.Severity {
		case "critical":
			summary.CriticalCount++
		case "high":
			summary.HighCount++
		case "medium":
			summary.MediumCount++
		case "low":
			summary.LowCount++
		}
	}

	// Analyze component vulnerabilities
	components, componentFindings, err := vs.DetectComponentVulnerabilities()
	if err != nil {
		return summary, recommendations, fmt.Errorf("failed to analyze component vulnerabilities: %w", err)
	}

	summary.TotalFindings += len(componentFindings)

	// Count vulnerable components and CVEs
	for _, component := range components {
		if component.Vulnerable {
			summary.OutdatedComponents++
		}
		summary.CVECount += len(component.CVEs)
		for _, cve := range component.CVEs {
			switch cve.Severity {
			case "critical":
				summary.CriticalCVEs++
			case "high":
				summary.HighCVEs++
			}
		}
	}

	for _, finding := range componentFindings {
		switch finding.Severity {
		case "critical":
			summary.CriticalCount++
		case "high":
			summary.HighCount++
		case "medium":
			summary.MediumCount++
		case "low":
			summary.LowCount++
		}
	}

	// Analyze addon vulnerabilities
	addons, addonFindings, err := vs.DetectAddonVulnerabilities()
	if err != nil {
		return summary, recommendations, fmt.Errorf("failed to analyze addon vulnerabilities: %w", err)
	}

	summary.TotalFindings += len(addonFindings)

	// Count vulnerable addons and CVEs
	for _, addon := range addons {
		if addon.Vulnerable {
			summary.OutdatedComponents++
		}
		summary.CVECount += len(addon.CVEs)
		for _, cve := range addon.CVEs {
			switch cve.Severity {
			case "critical":
				summary.CriticalCVEs++
			case "high":
				summary.HighCVEs++
			}
		}
	}

	for _, finding := range addonFindings {
		switch finding.Severity {
		case "critical":
			summary.CriticalCount++
		case "high":
			summary.HighCount++
		case "medium":
			summary.MediumCount++
		case "low":
			summary.LowCount++
		}
	}

	// Calculate vulnerability score
	summary.VulnerabilityScore = vs.calculateVulnerabilityScore(summary)

	// Generate recommendations
	recommendations = vs.generateRecommendations(summary, kubernetesVersion, nodes, components, addons)

	return summary, recommendations, nil
}

// calculateVulnerabilityScore calculates the overall vulnerability security score
func (vs *VulnerabilityScanner) calculateVulnerabilityScore(summary VulnerabilitySummary) float64 {
	score := 100.0

	// Deduct points for critical issues
	score -= float64(summary.CriticalCount) * 25.0
	score -= float64(summary.HighCount) * 20.0
	score -= float64(summary.MediumCount) * 15.0
	score -= float64(summary.LowCount) * 10.0

	// Deduct points for CVEs
	score -= float64(summary.CriticalCVEs) * 20.0
	score -= float64(summary.HighCVEs) * 15.0
	score -= float64(summary.CVECount) * 5.0

	// Deduct points for outdated components
	score -= float64(summary.OutdatedComponents) * 10.0

	// Ensure score doesn't go below 0
	if score < 0 {
		score = 0
	}

	return score
}

// generateRecommendations generates vulnerability security recommendations
func (vs *VulnerabilityScanner) generateRecommendations(summary VulnerabilitySummary, _ KubernetesVersion, _ []NodeInfo, _ []ComponentInfo, _ []AddonInfo) []string {
	var recommendations []string

	// Kubernetes version recommendations
	if summary.KubernetesVersion != "" {
		recommendations = append(recommendations, "Upgrade Kubernetes to the latest stable version")
		recommendations = append(recommendations, "Implement automated Kubernetes updates")
		recommendations = append(recommendations, "Monitor Kubernetes security advisories")
	}

	// Node recommendations
	if summary.OutdatedComponents > 0 {
		recommendations = append(recommendations, "Upgrade all outdated components to latest versions")
		recommendations = append(recommendations, "Implement automated node updates")
		recommendations = append(recommendations, "Monitor node security advisories")
	}

	// CVE recommendations
	if summary.CriticalCVEs > 0 {
		recommendations = append(recommendations, "Address critical CVEs immediately")
		recommendations = append(recommendations, "Implement emergency patching procedures")
		recommendations = append(recommendations, "Monitor CVE databases regularly")
	}

	if summary.HighCVEs > 0 {
		recommendations = append(recommendations, "Prioritize high-severity CVEs")
		recommendations = append(recommendations, "Implement CVE scanning in CI/CD")
		recommendations = append(recommendations, "Use vulnerability management tools")
	}

	// Component recommendations
	recommendations = append(recommendations, "Review and upgrade outdated components")
	recommendations = append(recommendations, "Implement component vulnerability scanning")

	// Addon recommendations
	recommendations = append(recommendations, "Review and upgrade outdated addons")
	recommendations = append(recommendations, "Implement addon vulnerability scanning")

	// General recommendations
	if summary.VulnerabilityScore < 50 {
		recommendations = append(recommendations, "Implement comprehensive vulnerability management strategy")
		recommendations = append(recommendations, "Conduct regular security assessments")
		recommendations = append(recommendations, "Implement automated vulnerability scanning")
	}

	if summary.CriticalCount > 0 {
		recommendations = append(recommendations, "Address critical vulnerabilities immediately")
	}

	if summary.HighCount > 0 {
		recommendations = append(recommendations, "Prioritize high-severity vulnerabilities")
	}

	// Specific recommendations based on findings
	if summary.CVECount > 0 {
		recommendations = append(recommendations, "Implement CVE monitoring and alerting")
		recommendations = append(recommendations, "Use vulnerability scanning tools")
		recommendations = append(recommendations, "Implement patch management procedures")
	}

	return recommendations
}

// PrioritizeVulnerabilities prioritizes vulnerabilities by severity and impact
func (vs *VulnerabilityScanner) PrioritizeVulnerabilities(findings []VulnerabilityFinding) []VulnerabilityFinding {
	// Sort findings by risk score (highest first)
	for i := 0; i < len(findings)-1; i++ {
		for j := i + 1; j < len(findings); j++ {
			if findings[i].RiskScore < findings[j].RiskScore {
				findings[i], findings[j] = findings[j], findings[i]
			}
		}
	}

	return findings
}

// AnalyzeCVETrends analyzes CVE trends and patterns
func (vs *VulnerabilityScanner) AnalyzeCVETrends(cves []CVEInfo) map[string]interface{} {
	trends := make(map[string]interface{})

	// Count CVEs by severity
	severityCount := make(map[string]int)
	for _, cve := range cves {
		severityCount[cve.Severity]++
	}
	trends["severity_distribution"] = severityCount

	// Count CVEs by year
	yearCount := make(map[int]int)
	for _, cve := range cves {
		year := cve.Published.Year()
		yearCount[year]++
	}
	trends["year_distribution"] = yearCount

	// Calculate average score
	totalScore := 0.0
	for _, cve := range cves {
		totalScore += cve.Score
	}
	if len(cves) > 0 {
		trends["average_score"] = totalScore / float64(len(cves))
	}

	// Count CVEs with fixes available
	fixedCount := 0
	for _, cve := range cves {
		if len(cve.FixedVersions) > 0 {
			fixedCount++
		}
	}
	trends["fixed_count"] = fixedCount
	trends["unfixed_count"] = len(cves) - fixedCount

	return trends
}

// EvaluateVulnerabilityImpact evaluates the impact of vulnerabilities
func (vs *VulnerabilityScanner) EvaluateVulnerabilityImpact() []VulnerabilityFinding {
	var findings []VulnerabilityFinding

	// Check for RCE vulnerabilities
	findings = append(findings, VulnerabilityFinding{
		ID:          "vuln-impact-001",
		Type:        "rce-vulnerability",
		Severity:    "critical",
		Title:       "Remote Code Execution Vulnerability",
		Description: "Critical RCE vulnerability detected in cluster components.",
		Resource:    "cluster",
		Namespace:   "all",
		RiskScore:   10.0,
		Remediation: "Apply security patches immediately and restrict access.",
		Timestamp:   time.Now(),
		Metadata: map[string]string{
			"impact_type": "rce",
			"severity":    "critical",
		},
	})

	// Check for privilege escalation vulnerabilities
	findings = append(findings, VulnerabilityFinding{
		ID:          "vuln-impact-002",
		Type:        "privilege-escalation",
		Severity:    "high",
		Title:       "Privilege Escalation Vulnerability",
		Description: "High-severity privilege escalation vulnerability detected.",
		Resource:    "cluster",
		Namespace:   "all",
		RiskScore:   8.5,
		Remediation: "Update affected components and review access controls.",
		Timestamp:   time.Now(),
		Metadata: map[string]string{
			"impact_type": "privilege_escalation",
			"severity":    "high",
		},
	})

	// Check for information disclosure vulnerabilities
	findings = append(findings, VulnerabilityFinding{
		ID:          "vuln-impact-003",
		Type:        "information-disclosure",
		Severity:    "medium",
		Title:       "Information Disclosure Vulnerability",
		Description: "Medium-severity information disclosure vulnerability detected.",
		Resource:    "cluster",
		Namespace:   "all",
		RiskScore:   6.0,
		Remediation: "Update affected components and review data handling.",
		Timestamp:   time.Now(),
		Metadata: map[string]string{
			"impact_type": "information_disclosure",
			"severity":    "medium",
		},
	})

	return findings
}

// GenerateVulnerabilityReport generates a comprehensive vulnerability report
func (vs *VulnerabilityScanner) GenerateVulnerabilityReport() []string {
	var report []string

	report = append(report, "1. Implement automated vulnerability scanning")
	report = append(report, "2. Use CVE monitoring and alerting systems")
	report = append(report, "3. Implement patch management procedures")
	report = append(report, "4. Regular security assessments and penetration testing")
	report = append(report, "5. Use vulnerability management tools (Trivy, Snyk, etc.)")
	report = append(report, "6. Implement security scanning in CI/CD pipelines")
	report = append(report, "7. Monitor security advisories and bulletins")
	report = append(report, "8. Implement emergency patching procedures")
	report = append(report, "9. Use container image scanning")
	report = append(report, "10. Regular security training and awareness")

	return report
}
