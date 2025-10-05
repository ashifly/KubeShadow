package k08_secrets

import (
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// AnalyzeSecretManagement analyzes secret management security posture
func (ss *SecretScanner) AnalyzeSecretManagement() (SecretSummary, []string, error) {
	var recommendations []string
	summary := SecretSummary{}

	// Analyze raw secrets
	secrets, configMapSecrets, secretFindings, err := ss.DetectRawSecrets()
	if err != nil {
		return summary, recommendations, fmt.Errorf("failed to analyze raw secrets: %w", err)
	}

	summary.RawSecretsFound = len(secrets)
	summary.ConfigMapSecrets = len(configMapSecrets)
	summary.TotalFindings += len(secretFindings)

	// Count findings by severity
	for _, finding := range secretFindings {
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

	// Analyze image pull secrets
	imagePullSecrets, imagePullFindings, err := ss.DetectImagePullSecrets()
	if err != nil {
		return summary, recommendations, fmt.Errorf("failed to analyze image pull secrets: %w", err)
	}

	summary.WeakImagePullSecrets = len(imagePullSecrets)
	summary.TotalFindings += len(imagePullFindings)

	for _, finding := range imagePullFindings {
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

	// Analyze etcd encryption
	etcdEncryption, etcdFindings, err := ss.DetectEtcdEncryption()
	if err != nil {
		return summary, recommendations, fmt.Errorf("failed to analyze etcd encryption: %w", err)
	}

	summary.EtcdEncryptionEnabled = etcdEncryption.Enabled
	summary.TotalFindings += len(etcdFindings)

	for _, finding := range etcdFindings {
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

	// Analyze KMS encryption
	kmsEncryption, kmsFindings, err := ss.DetectKMSEncryption()
	if err != nil {
		return summary, recommendations, fmt.Errorf("failed to analyze KMS encryption: %w", err)
	}

	summary.KMSEncryptionEnabled = kmsEncryption.Enabled
	summary.TotalFindings += len(kmsFindings)

	for _, finding := range kmsFindings {
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

	// Analyze vaults
	vaults, vaultFindings, err := ss.DetectVaults()
	if err != nil {
		return summary, recommendations, fmt.Errorf("failed to analyze vaults: %w", err)
	}

	summary.ExposedSecrets += len(vaults)
	summary.TotalFindings += len(vaultFindings)

	for _, finding := range vaultFindings {
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

	// Calculate secret score
	summary.SecretScore = ss.calculateSecretScore(summary)

	// Generate recommendations
	recommendations = ss.generateRecommendations(summary, secrets, configMapSecrets, imagePullSecrets, etcdEncryption, kmsEncryption, vaults)

	return summary, recommendations, nil
}

// calculateSecretScore calculates the overall secret management security score
func (ss *SecretScanner) calculateSecretScore(summary SecretSummary) float64 {
	score := 100.0

	// Deduct points for critical issues
	score -= float64(summary.CriticalCount) * 25.0
	score -= float64(summary.HighCount) * 20.0
	score -= float64(summary.MediumCount) * 15.0
	score -= float64(summary.LowCount) * 10.0

	// Deduct points for specific issues
	if summary.RawSecretsFound > 0 {
		score -= float64(summary.RawSecretsFound) * 15.0
	}
	if summary.ConfigMapSecrets > 0 {
		score -= float64(summary.ConfigMapSecrets) * 20.0
	}
	if summary.ExposedSecrets > 0 {
		score -= float64(summary.ExposedSecrets) * 10.0
	}
	if !summary.EtcdEncryptionEnabled {
		score -= 20.0
	}
	if !summary.KMSEncryptionEnabled {
		score -= 15.0
	}
	if summary.WeakImagePullSecrets > 0 {
		score -= float64(summary.WeakImagePullSecrets) * 5.0
	}

	// Ensure score doesn't go below 0
	if score < 0 {
		score = 0
	}

	return score
}

// generateRecommendations generates secret management recommendations
func (ss *SecretScanner) generateRecommendations(summary SecretSummary, _ []SecretInfo, _ []ConfigMapSecret, _ []ImagePullSecret, _ EtcdEncryption, _ KMSEncryption, _ []VaultInfo) []string {
	var recommendations []string

	// Raw secrets recommendations
	if summary.RawSecretsFound > 0 {
		recommendations = append(recommendations, "Remove raw secrets from environment variables and ConfigMaps")
		recommendations = append(recommendations, "Use proper secret management tools (Vault, AWS Secrets Manager, etc.)")
		recommendations = append(recommendations, "Implement secret rotation policies")
	}

	// ConfigMap secrets recommendations
	if summary.ConfigMapSecrets > 0 {
		recommendations = append(recommendations, "Move secrets from ConfigMaps to Secret resources")
		recommendations = append(recommendations, "Use ConfigMaps only for non-sensitive configuration data")
		recommendations = append(recommendations, "Implement proper secret management practices")
	}

	// Encryption recommendations
	if !summary.EtcdEncryptionEnabled {
		recommendations = append(recommendations, "Enable etcd encryption at rest")
		recommendations = append(recommendations, "Configure encryption providers (aescbc, secretbox)")
		recommendations = append(recommendations, "Implement key rotation for etcd encryption")
	}

	if !summary.KMSEncryptionEnabled {
		recommendations = append(recommendations, "Enable KMS encryption for secrets")
		recommendations = append(recommendations, "Use cloud provider KMS services")
		recommendations = append(recommendations, "Implement envelope encryption for secrets")
	}

	// Image pull secrets recommendations
	if summary.WeakImagePullSecrets > 0 {
		recommendations = append(recommendations, "Limit image pull secret scope to specific namespaces")
		recommendations = append(recommendations, "Use least privilege principle for image pull secrets")
		recommendations = append(recommendations, "Regularly rotate image pull secret credentials")
	}

	// Vault recommendations
	recommendations = append(recommendations, "Secure vault configuration and access")
	recommendations = append(recommendations, "Use proper authentication for vault access")
	recommendations = append(recommendations, "Implement vault access logging and monitoring")

	// General recommendations
	if summary.SecretScore < 50 {
		recommendations = append(recommendations, "Implement comprehensive secret management strategy")
		recommendations = append(recommendations, "Conduct secret management security assessment")
		recommendations = append(recommendations, "Train teams on secure secret handling practices")
	}

	if summary.CriticalCount > 0 {
		recommendations = append(recommendations, "Address critical secret management issues immediately")
	}

	if summary.HighCount > 0 {
		recommendations = append(recommendations, "Prioritize high-severity secret management issues")
	}

	// Specific recommendations based on findings
	if summary.ExposedSecrets > 0 {
		recommendations = append(recommendations, "Implement secret scanning in CI/CD pipelines")
		recommendations = append(recommendations, "Use tools like GitLeaks or TruffleHog for secret detection")
	}

	return recommendations
}

// AnalyzeSecretUsage analyzes how secrets are being used
func (ss *SecretScanner) AnalyzeSecretUsage(secretName, namespace string) ([]SecretUsage, error) {
	var usage []SecretUsage

	// Get all pods to check secret usage
	pods, err := ss.client.CoreV1().Pods("").List(ss.ctx, metav1.ListOptions{})
	if err != nil {
		return usage, fmt.Errorf("failed to list pods: %w", err)
	}

	for _, pod := range pods.Items {
		// Check if secret is used as environment variable
		for _, container := range pod.Spec.Containers {
			for _, env := range container.Env {
				if env.ValueFrom != nil && env.ValueFrom.SecretKeyRef != nil {
					if env.ValueFrom.SecretKeyRef.Name == secretName {
						usage = append(usage, SecretUsage{
							Resource:    fmt.Sprintf("pod/%s", pod.Name),
							Namespace:   pod.Namespace,
							Type:        "environment",
							Environment: env.Name,
							Metadata: map[string]string{
								"container": container.Name,
								"pod":       pod.Name,
							},
						})
					}
				}
			}
		}

		// Check if secret is used as volume
		for _, volume := range pod.Spec.Volumes {
			if volume.Secret != nil && volume.Secret.SecretName == secretName {
				usage = append(usage, SecretUsage{
					Resource:  fmt.Sprintf("pod/%s", pod.Name),
					Namespace: pod.Namespace,
					Type:      "volume",
					Volume:    volume.Name,
					Metadata: map[string]string{
						"pod": pod.Name,
					},
				})
			}
		}
	}

	return usage, nil
}

// EvaluateSecretSecurity evaluates the security of secret management
func (ss *SecretScanner) EvaluateSecretSecurity() []SecretFinding {
	var findings []SecretFinding

	// Check for secrets in environment variables
	pods, err := ss.client.CoreV1().Pods("").List(ss.ctx, metav1.ListOptions{})
	if err == nil {
		for _, pod := range pods.Items {
			for _, container := range pod.Spec.Containers {
				for _, env := range container.Env {
					if env.Value != "" && ss.isLikelySecret(env.Value, ss.getSecretPatterns()) {
						findings = append(findings, SecretFinding{
							ID:          "secret-security-001",
							Type:        "env-secret",
							Severity:    "critical",
							Title:       "Secret in Environment Variable",
							Description: fmt.Sprintf("Pod %s/%s has secret in environment variable %s.", pod.Namespace, pod.Name, env.Name),
							Resource:    fmt.Sprintf("pod/%s", pod.Name),
							Namespace:   pod.Namespace,
							RiskScore:   9.0,
							Remediation: "Move secret from environment variable to Secret resource.",
							Timestamp:   time.Now(),
							Metadata: map[string]string{
								"container": container.Name,
								"env_var":   env.Name,
							},
						})
					}
				}
			}
		}
	}

	// Check for secrets in ConfigMaps
	configMaps, err := ss.client.CoreV1().ConfigMaps("").List(ss.ctx, metav1.ListOptions{})
	if err == nil {
		for _, cm := range configMaps.Items {
			for key, value := range cm.Data {
				if ss.isLikelySecret(value, ss.getSecretPatterns()) {
					findings = append(findings, SecretFinding{
						ID:          "secret-security-002",
						Type:        "configmap-secret",
						Severity:    "critical",
						Title:       "Secret in ConfigMap",
						Description: fmt.Sprintf("ConfigMap %s/%s contains secret in key %s.", cm.Namespace, cm.Name, key),
						Resource:    fmt.Sprintf("configmap/%s", cm.Name),
						Namespace:   cm.Namespace,
						RiskScore:   9.5,
						Remediation: "Move secret from ConfigMap to Secret resource.",
						Timestamp:   time.Now(),
						Metadata: map[string]string{
							"configmap_key": key,
						},
					})
				}
			}
		}
	}

	return findings
}

// GenerateSecretManagementRecommendations generates specific secret management recommendations
func (ss *SecretScanner) GenerateSecretManagementRecommendations() []string {
	var recommendations []string

	recommendations = append(recommendations, "1. Use proper Secret resources instead of ConfigMaps for sensitive data")
	recommendations = append(recommendations, "2. Enable etcd encryption at rest")
	recommendations = append(recommendations, "3. Implement KMS encryption for secrets")
	recommendations = append(recommendations, "4. Use external secret management tools (Vault, AWS Secrets Manager)")
	recommendations = append(recommendations, "5. Implement secret rotation policies")
	recommendations = append(recommendations, "6. Use least privilege principle for secret access")
	recommendations = append(recommendations, "7. Monitor and audit secret access")
	recommendations = append(recommendations, "8. Implement secret scanning in CI/CD pipelines")
	recommendations = append(recommendations, "9. Use secretless patterns where possible")
	recommendations = append(recommendations, "10. Regular security assessments of secret management")

	return recommendations
}
