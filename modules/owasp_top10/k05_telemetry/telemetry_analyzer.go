package k05_telemetry

import (
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// AnalyzeTelemetryCoverage analyzes the coverage of telemetry and logging
func (ts *TelemetryScanner) AnalyzeTelemetryCoverage() (TelemetrySummary, []string, error) {
	var recommendations []string
	summary := TelemetrySummary{}

	// Analyze audit logging coverage
	auditPolicy, auditFindings, err := ts.DetectAuditLogging()
	if err != nil {
		return summary, recommendations, fmt.Errorf("failed to analyze audit logging: %w", err)
	}

	summary.AuditEnabled = auditPolicy.Enabled
	summary.TotalFindings += len(auditFindings)

	// Count findings by severity
	for _, finding := range auditFindings {
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

	// Analyze eBPF coverage
	ebProbes, ebpfFindings, err := ts.DetectEBProbes()
	if err != nil {
		return summary, recommendations, fmt.Errorf("failed to analyze eBPF probes: %w", err)
	}

	summary.EBPFEnabled = len(ebProbes) > 0
	summary.TotalFindings += len(ebpfFindings)

	for _, finding := range ebpfFindings {
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

	// Analyze SIEM integration
	siemIntegration, logSinks, siemFindings, err := ts.DetectSIEMIntegration()
	if err != nil {
		return summary, recommendations, fmt.Errorf("failed to analyze SIEM integration: %w", err)
	}

	summary.SIEMIntegration = siemIntegration.Enabled
	summary.TotalFindings += len(siemFindings)

	for _, finding := range siemFindings {
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

	// Analyze log retention
	retentionFindings, err := ts.DetectLogRetention()
	if err != nil {
		return summary, recommendations, fmt.Errorf("failed to analyze log retention: %w", err)
	}

	summary.TotalFindings += len(retentionFindings)

	for _, finding := range retentionFindings {
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

	// Calculate coverage scores
	summary.CoverageScore = ts.calculateCoverageScore(auditPolicy, ebProbes, siemIntegration, logSinks)
	summary.RetentionScore = ts.calculateRetentionScore(logSinks)

	// Count namespaces and events
	summary.NamespacesCovered = ts.countCoveredNamespaces()
	summary.EventsLogged = ts.countLoggedEvents()

	// Generate recommendations
	recommendations = ts.generateRecommendations(summary, auditPolicy, ebProbes, siemIntegration)

	return summary, recommendations, nil
}

// calculateCoverageScore calculates the overall telemetry coverage score
func (ts *TelemetryScanner) calculateCoverageScore(auditPolicy AuditPolicy, ebProbes []EBProbe, siemIntegration SIEMIntegration, logSinks []LogSink) float64 {
	score := 0.0
	maxScore := 4.0

	// Audit logging (25%)
	if auditPolicy.Enabled {
		score += 1.0
	}

	// eBPF monitoring (25%)
	if len(ebProbes) > 0 {
		score += 1.0
	}

	// SIEM integration (25%)
	if siemIntegration.Enabled {
		score += 1.0
	}

	// Log sinks (25%)
	if len(logSinks) > 0 {
		score += 1.0
	}

	return (score / maxScore) * 100
}

// calculateRetentionScore calculates the log retention score
func (ts *TelemetryScanner) calculateRetentionScore(logSinks []LogSink) float64 {
	if len(logSinks) == 0 {
		return 0.0
	}

	totalRetention := 0
	validSinks := 0

	for _, sink := range logSinks {
		if sink.Retention > 0 {
			totalRetention += sink.Retention
			validSinks++
		}
	}

	if validSinks == 0 {
		return 0.0
	}

	avgRetention := float64(totalRetention) / float64(validSinks)

	// Score based on retention period (30 days = 100%, 7 days = 70%, 1 day = 30%)
	if avgRetention >= 30 {
		return 100.0
	} else if avgRetention >= 7 {
		return 70.0
	} else if avgRetention >= 1 {
		return 30.0
	}

	return 10.0
}

// countCoveredNamespaces counts the number of namespaces with telemetry coverage
func (ts *TelemetryScanner) countCoveredNamespaces() int {
	namespaces, err := ts.client.CoreV1().Namespaces().List(ts.ctx, metav1.ListOptions{})
	if err != nil {
		return 0
	}

	covered := 0
	for _, ns := range namespaces.Items {
		// Check if namespace has audit logging
		if ts.namespaceHasAuditLogging(ns.Name) {
			covered++
		}
	}

	return covered
}

// countLoggedEvents estimates the number of logged events
func (ts *TelemetryScanner) countLoggedEvents() int {
	// This is a simplified estimation
	// In a real implementation, you would query metrics or logs
	pods, err := ts.client.CoreV1().Pods("").List(ts.ctx, metav1.ListOptions{})
	if err != nil {
		return 0
	}

	// Estimate based on number of pods and namespaces
	namespaces, err := ts.client.CoreV1().Namespaces().List(ts.ctx, metav1.ListOptions{})
	if err != nil {
		return 0
	}

	// Rough estimation: 100 events per pod per day
	return len(pods.Items) * len(namespaces.Items) * 100
}

// namespaceHasAuditLogging checks if a namespace has audit logging enabled
func (ts *TelemetryScanner) namespaceHasAuditLogging(namespace string) bool {
	// Check for audit-related resources in the namespace
	configMaps, err := ts.client.CoreV1().ConfigMaps(namespace).List(ts.ctx, metav1.ListOptions{
		LabelSelector: "audit=true",
	})
	if err != nil {
		return false
	}

	return len(configMaps.Items) > 0
}

// generateRecommendations generates recommendations based on the analysis
func (ts *TelemetryScanner) generateRecommendations(summary TelemetrySummary, _ AuditPolicy, _ []EBProbe, _ SIEMIntegration) []string {
	var recommendations []string

	if !summary.AuditEnabled {
		recommendations = append(recommendations, "Enable Kubernetes audit logging with comprehensive audit policy")
		recommendations = append(recommendations, "Configure audit webhook to forward audit logs to external systems")
	}

	if !summary.EBPFEnabled {
		recommendations = append(recommendations, "Deploy Falco with eBPF driver for runtime security monitoring")
		recommendations = append(recommendations, "Consider deploying Tetragon for additional eBPF-based observability")
	}

	if !summary.SIEMIntegration {
		recommendations = append(recommendations, "Integrate with SIEM solution for centralized security monitoring")
		recommendations = append(recommendations, "Configure log forwarding to cloud provider logging services")
	}

	if summary.CoverageScore < 50 {
		recommendations = append(recommendations, "Improve overall telemetry coverage by implementing missing components")
	}

	if summary.RetentionScore < 50 {
		recommendations = append(recommendations, "Configure appropriate log retention policies")
		recommendations = append(recommendations, "Implement log rotation to prevent disk space issues")
	}

	if summary.CriticalCount > 0 {
		recommendations = append(recommendations, "Address critical telemetry gaps immediately")
	}

	if summary.HighCount > 0 {
		recommendations = append(recommendations, "Prioritize high-severity telemetry issues")
	}

	return recommendations
}
