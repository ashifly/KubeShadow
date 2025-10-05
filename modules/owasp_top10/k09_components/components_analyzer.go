package k09_components

import (
	"fmt"
	"time"
)

// AnalyzeComponentMisconfigurations analyzes component misconfigurations
func (cs *ComponentScanner) AnalyzeComponentMisconfigurations() (ComponentSummary, []string, error) {
	var recommendations []string
	summary := ComponentSummary{}

	// Analyze webhooks
	webhooks, webhookFindings, err := cs.DetectWebhooks()
	if err != nil {
		return summary, recommendations, fmt.Errorf("failed to analyze webhooks: %w", err)
	}

	summary.WebhookCount = len(webhooks)
	summary.TotalFindings += len(webhookFindings)

	// Count webhook types
	for _, webhook := range webhooks {
		switch webhook.Type {
		case "MutatingWebhook":
			summary.MutatingWebhooks++
		case "ValidatingWebhook":
			summary.ValidatingWebhooks++
		}
		summary.AdmissionWebhooks++

		// Check for misconfigurations
		if webhook.RiskLevel == "high" || webhook.RiskLevel == "medium" {
			summary.MisconfiguredWebhooks++
		}
	}

	// Count findings by severity
	for _, finding := range webhookFindings {
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

	// Analyze CRDs
	crds, crdFindings, err := cs.DetectCRDs()
	if err != nil {
		return summary, recommendations, fmt.Errorf("failed to analyze CRDs: %w", err)
	}

	summary.CRDCount = len(crds)
	summary.TotalFindings += len(crdFindings)

	// Count risky CRDs
	for _, crd := range crds {
		if crd.RiskLevel == "high" {
			summary.RiskyCRDs++
		}
	}

	for _, finding := range crdFindings {
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

	// Analyze controllers
	controllers, controllerFindings, err := cs.DetectControllers()
	if err != nil {
		return summary, recommendations, fmt.Errorf("failed to analyze controllers: %w", err)
	}

	summary.TotalFindings += len(controllerFindings)

	// Count outdated controllers
	for _, controller := range controllers {
		if controller.Outdated {
			summary.OutdatedControllers++
		}
	}

	for _, finding := range controllerFindings {
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

	// Calculate component score
	summary.ComponentScore = cs.calculateComponentScore(summary, webhooks, crds, controllers)

	// Generate recommendations
	recommendations = cs.generateRecommendations(summary, webhooks, crds, controllers)

	return summary, recommendations, nil
}

// calculateComponentScore calculates the overall component security score
func (cs *ComponentScanner) calculateComponentScore(summary ComponentSummary, webhooks []WebhookInfo, _ []CRDInfo, _ []ControllerInfo) float64 {
	score := 100.0

	// Deduct points for critical issues
	score -= float64(summary.CriticalCount) * 20.0
	score -= float64(summary.HighCount) * 15.0
	score -= float64(summary.MediumCount) * 10.0
	score -= float64(summary.LowCount) * 5.0

	// Deduct points for specific issues
	if summary.MisconfiguredWebhooks > 0 {
		score -= float64(summary.MisconfiguredWebhooks) * 10.0
	}
	if summary.RiskyCRDs > 0 {
		score -= float64(summary.RiskyCRDs) * 15.0
	}
	if summary.OutdatedControllers > 0 {
		score -= float64(summary.OutdatedControllers) * 8.0
	}

	// Deduct points for webhook misconfigurations
	for _, webhook := range webhooks {
		if webhook.CABundle == "" {
			score -= 15.0
		}
		if webhook.FailurePolicy == "Ignore" {
			score -= 10.0
		}
	}

	// Ensure score doesn't go below 0
	if score < 0 {
		score = 0
	}

	return score
}

// generateRecommendations generates component security recommendations
func (cs *ComponentScanner) generateRecommendations(summary ComponentSummary, webhooks []WebhookInfo, _ []CRDInfo, _ []ControllerInfo) []string {
	var recommendations []string

	// Webhook recommendations
	if summary.MisconfiguredWebhooks > 0 {
		recommendations = append(recommendations, "Configure CABundle for all webhooks")
		recommendations = append(recommendations, "Use Fail failure policy instead of Ignore")
		recommendations = append(recommendations, "Implement proper webhook certificate rotation")
		recommendations = append(recommendations, "Use namespaceSelector to restrict webhook scope")
	}

	// CRD recommendations
	if summary.RiskyCRDs > 0 {
		recommendations = append(recommendations, "Review CRD permissions and access controls")
		recommendations = append(recommendations, "Implement RBAC for CRD access")
		recommendations = append(recommendations, "Use validation schemas for CRDs")
		recommendations = append(recommendations, "Restrict CRD scope where possible")
	}

	// Controller recommendations
	if summary.OutdatedControllers > 0 {
		recommendations = append(recommendations, "Update outdated controllers to latest versions")
		recommendations = append(recommendations, "Implement automated controller updates")
		recommendations = append(recommendations, "Monitor controller versions regularly")
	}

	// General recommendations
	if summary.ComponentScore < 50 {
		recommendations = append(recommendations, "Implement comprehensive component security assessment")
		recommendations = append(recommendations, "Regular security reviews of cluster components")
		recommendations = append(recommendations, "Implement component monitoring and alerting")
	}

	if summary.CriticalCount > 0 {
		recommendations = append(recommendations, "Address critical component misconfigurations immediately")
	}

	if summary.HighCount > 0 {
		recommendations = append(recommendations, "Prioritize high-severity component issues")
	}

	// Specific webhook recommendations
	for _, webhook := range webhooks {
		if webhook.CABundle == "" {
			recommendations = append(recommendations, fmt.Sprintf("Configure CABundle for webhook %s", webhook.Name))
		}
		if webhook.FailurePolicy == "Ignore" {
			recommendations = append(recommendations, fmt.Sprintf("Change failure policy for webhook %s from Ignore to Fail", webhook.Name))
		}
	}

	return recommendations
}

// AnalyzeWebhookRisks analyzes webhook risks
func (cs *ComponentScanner) AnalyzeWebhookRisks(webhooks []WebhookInfo) []WebhookRisk {
	var risks []WebhookRisk

	for _, webhook := range webhooks {
		risk := WebhookRisk{
			WebhookName:     webhook.Name,
			RiskLevel:       webhook.RiskLevel,
			Issues:          []string{},
			Recommendations: []string{},
			Metadata:        make(map[string]string),
		}

		// Calculate risk score
		risk.RiskScore = cs.calculateWebhookRiskScore(webhook)

		// Identify issues
		if webhook.CABundle == "" {
			risk.Issues = append(risk.Issues, "Missing CABundle")
			risk.Recommendations = append(risk.Recommendations, "Configure CABundle for secure communication")
		}

		if webhook.FailurePolicy == "Ignore" {
			risk.Issues = append(risk.Issues, "Ignore failure policy")
			risk.Recommendations = append(risk.Recommendations, "Use Fail failure policy for better security")
		}

		// Check for broad API groups
		for _, rule := range webhook.Rules {
			if len(rule.APIGroups) == 0 || contains(rule.APIGroups, "*") {
				risk.Issues = append(risk.Issues, "Broad API group access")
				risk.Recommendations = append(risk.Recommendations, "Restrict API group access to specific groups")
			}
		}

		// Check for broad resources
		for _, rule := range webhook.Rules {
			if len(rule.Resources) == 0 || contains(rule.Resources, "*") {
				risk.Issues = append(risk.Issues, "Broad resource access")
				risk.Recommendations = append(risk.Recommendations, "Restrict resource access to specific resources")
			}
		}

		// Check for broad operations
		for _, rule := range webhook.Rules {
			if len(rule.Operations) == 0 || contains(rule.Operations, "*") {
				risk.Issues = append(risk.Issues, "Broad operation access")
				risk.Recommendations = append(risk.Recommendations, "Restrict operation access to specific operations")
			}
		}

		// Check namespace selector
		if webhook.NamespaceSelector == nil {
			risk.Issues = append(risk.Issues, "No namespace selector")
			risk.Recommendations = append(risk.Recommendations, "Use namespaceSelector to restrict webhook scope")
		}

		// Check object selector
		if webhook.ObjectSelector == nil {
			risk.Issues = append(risk.Issues, "No object selector")
			risk.Recommendations = append(risk.Recommendations, "Use objectSelector to restrict webhook scope")
		}

		risks = append(risks, risk)
	}

	return risks
}

// calculateWebhookRiskScore calculates the risk score for a webhook
func (cs *ComponentScanner) calculateWebhookRiskScore(webhook WebhookInfo) float64 {
	score := 0.0

	// Base score
	score += 10.0

	// CABundle issues
	if webhook.CABundle == "" {
		score += 30.0
	}

	// Failure policy issues
	if webhook.FailurePolicy == "Ignore" {
		score += 20.0
	}

	// Broad access issues
	for _, rule := range webhook.Rules {
		if len(rule.APIGroups) == 0 || contains(rule.APIGroups, "*") {
			score += 15.0
		}
		if len(rule.Resources) == 0 || contains(rule.Resources, "*") {
			score += 15.0
		}
		if len(rule.Operations) == 0 || contains(rule.Operations, "*") {
			score += 15.0
		}
	}

	// Selector issues
	if webhook.NamespaceSelector == nil {
		score += 10.0
	}
	if webhook.ObjectSelector == nil {
		score += 10.0
	}

	return score
}

// EvaluateComponentSecurity evaluates the security of cluster components
func (cs *ComponentScanner) EvaluateComponentSecurity() []ComponentFinding {
	var findings []ComponentFinding

	// Check for webhook misconfigurations
	webhooks, _, err := cs.DetectWebhooks()
	if err == nil {
		for _, webhook := range webhooks {
			if webhook.CABundle == "" {
				findings = append(findings, ComponentFinding{
					ID:          "component-security-001",
					Type:        "webhook-security",
					Severity:    "high",
					Title:       "Webhook Security Issue",
					Description: fmt.Sprintf("Webhook %s has security misconfigurations.", webhook.Name),
					Resource:    fmt.Sprintf("webhook/%s", webhook.Name),
					Namespace:   webhook.Namespace,
					RiskScore:   8.0,
					Remediation: "Review and fix webhook security configurations.",
					Timestamp:   time.Now(),
					Metadata: map[string]string{
						"webhook_name": webhook.Name,
						"webhook_type": webhook.Type,
					},
				})
			}
		}
	}

	// Check for CRD security issues
	crds, _, err := cs.DetectCRDs()
	if err == nil {
		for _, crd := range crds {
			if crd.RiskLevel == "high" {
				findings = append(findings, ComponentFinding{
					ID:          "component-security-002",
					Type:        "crd-security",
					Severity:    "high",
					Title:       "CRD Security Issue",
					Description: fmt.Sprintf("CRD %s has security risks.", crd.Name),
					Resource:    fmt.Sprintf("crd/%s", crd.Name),
					Namespace:   "",
					RiskScore:   7.5,
					Remediation: "Review and secure CRD configurations.",
					Timestamp:   time.Now(),
					Metadata: map[string]string{
						"crd_name":  crd.Name,
						"crd_group": crd.Group,
					},
				})
			}
		}
	}

	return findings
}

// Helper function to check if slice contains string
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
