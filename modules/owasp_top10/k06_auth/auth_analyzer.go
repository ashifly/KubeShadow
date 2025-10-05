package k06_auth

import (
	"fmt"
	"strings"
	"time"
)

// AnalyzeAuthCoverage analyzes the overall authentication security posture
func (as *AuthScanner) AnalyzeAuthCoverage() (AuthSummary, []string, error) {
	var recommendations []string
	summary := AuthSummary{}

	// Analyze API server configuration
	apiConfig, apiFindings, err := as.DetectAPIServerAuth()
	if err != nil {
		return summary, recommendations, fmt.Errorf("failed to analyze API server auth: %w", err)
	}

	summary.TotalFindings += len(apiFindings)
	summary.AnonymousAccess = apiConfig.AnonymousAuth
	summary.WeakAuthMethods = as.countWeakAuthMethods(apiConfig)

	// Count findings by severity
	for _, finding := range apiFindings {
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

	// Analyze kubeconfig exposure
	kubeConfigs, kubeFindings, err := as.DetectKubeConfigs()
	if err != nil {
		return summary, recommendations, fmt.Errorf("failed to analyze kubeconfigs: %w", err)
	}

	summary.TotalFindings += len(kubeFindings)
	summary.ExposedCredentials += len(kubeConfigs)

	for _, finding := range kubeFindings {
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

	// Analyze tokens
	tokens, tokenFindings, err := as.DetectTokens()
	if err != nil {
		return summary, recommendations, fmt.Errorf("failed to analyze tokens: %w", err)
	}

	summary.TotalFindings += len(tokenFindings)
	summary.ExposedCredentials += len(tokens)
	summary.TokenAge = as.calculateAverageTokenAge(tokens)
	summary.CredentialRotation = as.checkCredentialRotation(tokens)

	for _, finding := range tokenFindings {
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

	// Analyze public endpoints
	endpoints, endpointFindings, err := as.DetectPublicEndpoints()
	if err != nil {
		return summary, recommendations, fmt.Errorf("failed to analyze public endpoints: %w", err)
	}

	summary.TotalFindings += len(endpointFindings)
	summary.PublicEndpoints = len(endpoints)

	for _, finding := range endpointFindings {
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

	// Calculate overall auth score
	summary.AuthScore = as.calculateAuthScore(summary, apiConfig)

	// Generate recommendations
	recommendations = as.generateRecommendations(summary, apiConfig, kubeConfigs, tokens, endpoints)

	return summary, recommendations, nil
}

// calculateAuthScore calculates the overall authentication security score
func (as *AuthScanner) calculateAuthScore(summary AuthSummary, _ APIServerConfig) float64 {
	score := 100.0

	// Deduct points for critical issues
	score -= float64(summary.CriticalCount) * 20.0
	score -= float64(summary.HighCount) * 15.0
	score -= float64(summary.MediumCount) * 10.0
	score -= float64(summary.LowCount) * 5.0

	// Deduct points for specific issues
	if summary.AnonymousAccess {
		score -= 30.0
	}
	if summary.WeakAuthMethods > 0 {
		score -= float64(summary.WeakAuthMethods) * 10.0
	}
	if summary.ExposedCredentials > 0 {
		score -= float64(summary.ExposedCredentials) * 15.0
	}
	if summary.PublicEndpoints > 0 {
		score -= float64(summary.PublicEndpoints) * 5.0
	}
	if summary.TokenAge > 30 {
		score -= 20.0
	}
	if !summary.CredentialRotation {
		score -= 15.0
	}

	// Ensure score doesn't go below 0
	if score < 0 {
		score = 0
	}

	return score
}

// countWeakAuthMethods counts weak authentication methods
func (as *AuthScanner) countWeakAuthMethods(apiConfig APIServerConfig) int {
	count := 0

	if apiConfig.AnonymousAuth {
		count++
	}
	if apiConfig.BasicAuth {
		count++
	}
	if !apiConfig.RBACEnabled {
		count++
	}
	if !apiConfig.AuditLogging {
		count++
	}

	return count
}

// calculateAverageTokenAge calculates the average age of tokens in days
func (as *AuthScanner) calculateAverageTokenAge(tokens []TokenInfo) int {
	if len(tokens) == 0 {
		return 0
	}

	totalAge := 0
	for _, token := range tokens {
		totalAge += int(token.Age.Hours() / 24)
	}

	return totalAge / len(tokens)
}

// checkCredentialRotation checks if credential rotation is implemented
func (as *AuthScanner) checkCredentialRotation(tokens []TokenInfo) bool {
	// Check if tokens are being rotated regularly
	// This is a simplified check - in reality, you'd analyze token creation/expiration patterns
	for _, token := range tokens {
		if token.Age < 7*24*time.Hour { // Tokens newer than 7 days
			return true
		}
	}
	return false
}

// generateRecommendations generates security recommendations
func (as *AuthScanner) generateRecommendations(summary AuthSummary, apiConfig APIServerConfig, kubeConfigs []KubeConfigInfo, tokens []TokenInfo, endpoints []PublicEndpoint) []string {
	var recommendations []string

	// API Server recommendations
	if summary.AnonymousAccess {
		recommendations = append(recommendations, "Disable anonymous access to Kubernetes API server")
	}
	if summary.WeakAuthMethods > 0 {
		recommendations = append(recommendations, "Implement strong authentication methods (OIDC, certificates)")
	}
	if !apiConfig.RBACEnabled {
		recommendations = append(recommendations, "Enable RBAC for fine-grained access control")
	}
	if !apiConfig.AuditLogging {
		recommendations = append(recommendations, "Enable comprehensive audit logging")
	}

	// Kubeconfig recommendations
	if len(kubeConfigs) > 0 {
		recommendations = append(recommendations, "Secure kubeconfig files with proper permissions")
		recommendations = append(recommendations, "Remove kubeconfigs from ConfigMaps and Secrets")
		recommendations = append(recommendations, "Implement kubeconfig rotation policies")
	}

	// Token recommendations
	if len(tokens) > 0 {
		recommendations = append(recommendations, "Review service account token permissions")
		recommendations = append(recommendations, "Implement token rotation policies")
		recommendations = append(recommendations, "Use least privilege principle for service accounts")
	}

	// Public endpoint recommendations
	if len(endpoints) > 0 {
		recommendations = append(recommendations, "Review public endpoint exposure")
		recommendations = append(recommendations, "Implement authentication for public services")
		recommendations = append(recommendations, "Use network policies to restrict access")
	}

	// General recommendations
	if summary.AuthScore < 50 {
		recommendations = append(recommendations, "Implement comprehensive authentication hardening")
		recommendations = append(recommendations, "Conduct security assessment of authentication mechanisms")
	}

	if summary.CriticalCount > 0 {
		recommendations = append(recommendations, "Address critical authentication vulnerabilities immediately")
	}

	if summary.HighCount > 0 {
		recommendations = append(recommendations, "Prioritize high-severity authentication issues")
	}

	// Specific recommendations based on findings
	if summary.TokenAge > 30 {
		recommendations = append(recommendations, "Implement regular token rotation (recommended: 30 days)")
	}

	if !summary.CredentialRotation {
		recommendations = append(recommendations, "Implement automated credential rotation")
	}

	return recommendations
}

// EvaluateTokenSecurity evaluates the security of service account tokens
func (as *AuthScanner) EvaluateTokenSecurity(tokens []TokenInfo) []AuthFinding {
	var findings []AuthFinding

	for _, token := range tokens {
		// Check token age
		if token.Age > 30*24*time.Hour {
			findings = append(findings, AuthFinding{
				ID:          "auth-token-001",
				Type:        "token-age",
				Severity:    "high",
				Title:       "Old Service Account Token",
				Description: fmt.Sprintf("Service account token %s is %v old and should be rotated.", token.Name, token.Age),
				Resource:    fmt.Sprintf("serviceaccount/%s", token.Name),
				Namespace:   token.Namespace,
				RiskScore:   7.5,
				Remediation: "Rotate service account tokens regularly (recommended: every 30 days).",
				Timestamp:   time.Now(),
				Metadata: map[string]string{
					"token_age": token.Age.String(),
					"expires":   token.Expires.Format(time.RFC3339),
				},
			})
		}

		// Check for excessive permissions
		if len(token.Permissions) > 10 {
			findings = append(findings, AuthFinding{
				ID:          "auth-token-002",
				Type:        "token-permissions",
				Severity:    "medium",
				Title:       "Excessive Token Permissions",
				Description: fmt.Sprintf("Service account token %s has %d permissions, which may violate least privilege.", token.Name, len(token.Permissions)),
				Resource:    fmt.Sprintf("serviceaccount/%s", token.Name),
				Namespace:   token.Namespace,
				RiskScore:   5.0,
				Remediation: "Review and reduce service account permissions to minimum required.",
				Timestamp:   time.Now(),
				Metadata: map[string]string{
					"permission_count": fmt.Sprintf("%d", len(token.Permissions)),
					"permissions":      fmt.Sprintf("%v", token.Permissions),
				},
			})
		}

		// Check for exposed tokens
		if token.Exposed {
			findings = append(findings, AuthFinding{
				ID:          "auth-token-003",
				Type:        "token-exposure",
				Severity:    "critical",
				Title:       "Exposed Service Account Token",
				Description: fmt.Sprintf("Service account token %s is exposed and accessible.", token.Name),
				Resource:    fmt.Sprintf("serviceaccount/%s", token.Name),
				Namespace:   token.Namespace,
				RiskScore:   9.0,
				Remediation: "Secure exposed tokens and implement proper access controls.",
				Timestamp:   time.Now(),
				Metadata: map[string]string{
					"location": token.Location,
					"exposed":  "true",
				},
			})
		}
	}

	return findings
}

// EvaluateKubeConfigSecurity evaluates the security of kubeconfig files
func (as *AuthScanner) EvaluateKubeConfigSecurity(kubeConfigs []KubeConfigInfo) []AuthFinding {
	var findings []AuthFinding

	for _, kubeConfig := range kubeConfigs {
		// Check for admin kubeconfigs
		if strings.Contains(kubeConfig.Path, "admin") {
			findings = append(findings, AuthFinding{
				ID:          "auth-kubeconfig-001",
				Type:        "kubeconfig-admin",
				Severity:    "critical",
				Title:       "Admin Kubeconfig Exposed",
				Description: fmt.Sprintf("Admin kubeconfig found at %s with high privileges.", kubeConfig.Path),
				Resource:    kubeConfig.Path,
				Namespace:   "all",
				RiskScore:   9.5,
				Remediation: "Secure admin kubeconfig files and restrict access to authorized personnel only.",
				Timestamp:   time.Now(),
				Metadata: map[string]string{
					"path":        kubeConfig.Path,
					"context":     kubeConfig.Context,
					"server":      kubeConfig.Server,
					"auth_method": kubeConfig.AuthMethod,
				},
			})
		}

		// Check for kubeconfigs in sensitive locations
		if strings.Contains(kubeConfig.Path, "/etc/") || strings.Contains(kubeConfig.Path, "/var/") {
			findings = append(findings, AuthFinding{
				ID:          "auth-kubeconfig-002",
				Type:        "kubeconfig-location",
				Severity:    "high",
				Title:       "Kubeconfig in System Directory",
				Description: fmt.Sprintf("Kubeconfig found in system directory %s.", kubeConfig.Path),
				Resource:    kubeConfig.Path,
				Namespace:   "all",
				RiskScore:   7.0,
				Remediation: "Move kubeconfig files to user home directory with proper permissions.",
				Timestamp:   time.Now(),
				Metadata: map[string]string{
					"path": kubeConfig.Path,
				},
			})
		}
	}

	return findings
}
