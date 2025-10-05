package k08_secrets

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"math"
	"regexp"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// NewSecretScanner creates a new secrets scanner
func NewSecretScanner(kubeconfig string, namespace string, labMode bool, confirm bool) (*SecretScanner, error) {
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

	return &SecretScanner{
		client:    clientset,
		namespace: namespace,
		ctx:       context.Background(),
		labMode:   labMode,
		confirm:   confirm,
	}, nil
}

// DetectRawSecrets detects raw secrets in environment variables and ConfigMaps
func (ss *SecretScanner) DetectRawSecrets() ([]SecretInfo, []ConfigMapSecret, []SecretFinding, error) {
	var findings []SecretFinding
	var secrets []SecretInfo
	var configMapSecrets []ConfigMapSecret

	// Get secret patterns for detection
	patterns := ss.getSecretPatterns()

	// Scan Secrets
	secretList, err := ss.client.CoreV1().Secrets("").List(ss.ctx, metav1.ListOptions{})
	if err != nil {
		return secrets, configMapSecrets, findings, fmt.Errorf("failed to list secrets: %w", err)
	}

	for _, secret := range secretList.Items {
		secretInfo := SecretInfo{
			Name:      secret.Name,
			Namespace: secret.Namespace,
			Type:      string(secret.Type),
			Source:    "Secret",
			Encrypted: false, // Kubernetes secrets are base64 encoded, not encrypted
			Metadata:  make(map[string]string),
		}

		// Analyze secret data
		for key, value := range secret.Data {
			// Check if value looks like a secret
			if ss.isLikelySecret(string(value), patterns) {
				secretInfo.Exposed = true
				secretInfo.RiskLevel = "high"
				secretInfo.RedactedValue = ss.redactSecret(string(value))

				// Only include actual value in lab mode with confirmation
				if ss.labMode && ss.confirm {
					secretInfo.Value = string(value)
				}

				findings = append(findings, SecretFinding{
					ID:          "secret-001",
					Type:        "raw-secret",
					Severity:    "high",
					Title:       "Raw Secret Detected",
					Description: fmt.Sprintf("Secret %s/%s contains raw secret data in key %s.", secret.Namespace, secret.Name, key),
					Resource:    fmt.Sprintf("secret/%s", secret.Name),
					Namespace:   secret.Namespace,
					RiskScore:   8.0,
					Remediation: "Use proper secret management tools and avoid storing raw secrets.",
					Timestamp:   time.Now(),
					Metadata: map[string]string{
						"secret_key":  key,
						"secret_type": string(secret.Type),
					},
				})
			}
		}

		secrets = append(secrets, secretInfo)
	}

	// Scan ConfigMaps for secrets
	configMapList, err := ss.client.CoreV1().ConfigMaps("").List(ss.ctx, metav1.ListOptions{})
	if err != nil {
		return secrets, configMapSecrets, findings, fmt.Errorf("failed to list configmaps: %w", err)
	}

	for _, cm := range configMapList.Items {
		for key, value := range cm.Data {
			if ss.isLikelySecret(value, patterns) {
				configMapSecret := ConfigMapSecret{
					ConfigMapName: cm.Name,
					Namespace:     cm.Namespace,
					Key:           key,
					RedactedValue: ss.redactSecret(value),
					Type:          "ConfigMap",
					RiskLevel:     "critical",
					Metadata:      make(map[string]string),
				}

				// Only include actual value in lab mode with confirmation
				if ss.labMode && ss.confirm {
					configMapSecret.Value = value
				}

				configMapSecrets = append(configMapSecrets, configMapSecret)

				findings = append(findings, SecretFinding{
					ID:          "secret-002",
					Type:        "configmap-secret",
					Severity:    "critical",
					Title:       "Secret in ConfigMap",
					Description: fmt.Sprintf("ConfigMap %s/%s contains secret data in key %s.", cm.Namespace, cm.Name, key),
					Resource:    fmt.Sprintf("configmap/%s", cm.Name),
					Namespace:   cm.Namespace,
					RiskScore:   9.5,
					Remediation: "Move secret data from ConfigMap to Secret resource.",
					Timestamp:   time.Now(),
					Metadata: map[string]string{
						"configmap_key":  key,
						"configmap_name": cm.Name,
					},
				})
			}
		}
	}

	return secrets, configMapSecrets, findings, nil
}

// DetectImagePullSecrets detects image pull secrets
func (ss *SecretScanner) DetectImagePullSecrets() ([]ImagePullSecret, []SecretFinding, error) {
	var findings []SecretFinding
	var imagePullSecrets []ImagePullSecret

	// Get all secrets
	secretList, err := ss.client.CoreV1().Secrets("").List(ss.ctx, metav1.ListOptions{})
	if err != nil {
		return imagePullSecrets, findings, fmt.Errorf("failed to list secrets: %w", err)
	}

	for _, secret := range secretList.Items {
		if secret.Type == corev1.SecretTypeDockerConfigJson || secret.Type == corev1.SecretTypeDockercfg {
			imagePullSecret := ImagePullSecret{
				Name:      secret.Name,
				Namespace: secret.Namespace,
				Type:      string(secret.Type),
				Scope:     "namespace", // Default scope
				RiskLevel: "medium",
				Metadata:  make(map[string]string),
			}

			// Analyze image pull secret scope and permissions
			if ss.isClusterWideImagePullSecret(secret) {
				imagePullSecret.Scope = "cluster"
				imagePullSecret.RiskLevel = "high"

				findings = append(findings, SecretFinding{
					ID:          "secret-003",
					Type:        "image-pull-secret",
					Severity:    "high",
					Title:       "Cluster-Wide Image Pull Secret",
					Description: fmt.Sprintf("Image pull secret %s/%s has cluster-wide scope.", secret.Namespace, secret.Name),
					Resource:    fmt.Sprintf("secret/%s", secret.Name),
					Namespace:   secret.Namespace,
					RiskScore:   7.5,
					Remediation: "Limit image pull secret scope to specific namespaces.",
					Timestamp:   time.Now(),
				})
			}

			imagePullSecrets = append(imagePullSecrets, imagePullSecret)
		}
	}

	return imagePullSecrets, findings, nil
}

// DetectEtcdEncryption detects etcd encryption status
func (ss *SecretScanner) DetectEtcdEncryption() (EtcdEncryption, []SecretFinding, error) {
	var findings []SecretFinding
	etcdEncryption := EtcdEncryption{
		Enabled:  false,
		Metadata: make(map[string]string),
	}

	// This is a simplified detection - in reality, you'd need to check etcd configuration
	// For now, we'll check if encryption providers are configured
	_, err := ss.client.CoreV1().ConfigMaps("kube-system").Get(ss.ctx, "encryption-config", metav1.GetOptions{})
	if err == nil {
		etcdEncryption.Enabled = true
		etcdEncryption.Providers = []string{"aescbc", "secretbox"}
	} else {
		findings = append(findings, SecretFinding{
			ID:          "secret-004",
			Type:        "etcd-encryption",
			Severity:    "high",
			Title:       "Etcd Encryption Not Enabled",
			Description: "Etcd encryption at rest is not enabled.",
			Resource:    "cluster",
			Namespace:   "all",
			RiskScore:   8.5,
			Remediation: "Enable etcd encryption at rest using encryption providers.",
			Timestamp:   time.Now(),
		})
	}

	return etcdEncryption, findings, nil
}

// DetectKMSEncryption detects KMS encryption status
func (ss *SecretScanner) DetectKMSEncryption() (KMSEncryption, []SecretFinding, error) {
	var findings []SecretFinding
	kmsEncryption := KMSEncryption{
		Enabled:  false,
		Metadata: make(map[string]string),
	}

	// Check for KMS encryption configuration
	// This is a simplified check - in reality, you'd need to check KMS configuration
	secrets, err := ss.client.CoreV1().Secrets("").List(ss.ctx, metav1.ListOptions{})
	if err == nil {
		// Look for KMS-encrypted secrets
		for _, secret := range secrets.Items {
			if secret.Annotations["encryption.k8s.io/v1"] != "" {
				kmsEncryption.Enabled = true
				kmsEncryption.Provider = "kms"
				break
			}
		}
	}

	if !kmsEncryption.Enabled {
		findings = append(findings, SecretFinding{
			ID:          "secret-005",
			Type:        "kms-encryption",
			Severity:    "medium",
			Title:       "KMS Encryption Not Enabled",
			Description: "KMS encryption for secrets is not enabled.",
			Resource:    "cluster",
			Namespace:   "all",
			RiskScore:   6.0,
			Remediation: "Enable KMS encryption for secrets using cloud provider KMS.",
			Timestamp:   time.Now(),
		})
	}

	return kmsEncryption, findings, nil
}

// DetectVaults detects external vault configurations
func (ss *SecretScanner) DetectVaults() ([]VaultInfo, []SecretFinding, error) {
	var findings []SecretFinding
	var vaults []VaultInfo

	// Check for Vault configurations in ConfigMaps and Secrets
	configMaps, err := ss.client.CoreV1().ConfigMaps("").List(ss.ctx, metav1.ListOptions{})
	if err == nil {
		for _, cm := range configMaps.Items {
			for key, value := range cm.Data {
				if strings.Contains(strings.ToLower(key), "vault") || strings.Contains(strings.ToLower(value), "vault") {
					vault := VaultInfo{
						Name:      fmt.Sprintf("%s-%s", cm.Name, key),
						Type:      "ConfigMap",
						URL:       ss.extractVaultURL(value),
						Exposed:   true,
						RiskLevel: "high",
						Metadata:  make(map[string]string),
					}

					vaults = append(vaults, vault)

					findings = append(findings, SecretFinding{
						ID:          "secret-006",
						Type:        "vault-exposure",
						Severity:    "high",
						Title:       "Vault Configuration Exposed",
						Description: fmt.Sprintf("Vault configuration found in ConfigMap %s/%s.", cm.Namespace, cm.Name),
						Resource:    fmt.Sprintf("configmap/%s", cm.Name),
						Namespace:   cm.Namespace,
						RiskScore:   7.0,
						Remediation: "Secure vault configuration and use proper secret management.",
						Timestamp:   time.Now(),
					})
				}
			}
		}
	}

	return vaults, findings, nil
}

// Helper methods for secret detection
func (ss *SecretScanner) getSecretPatterns() []SecretPattern {
	return []SecretPattern{
		{
			Name:        "API Key",
			Pattern:     `(?i)(api[_-]?key|apikey)\s*[:=]\s*['"]?([a-zA-Z0-9_-]{20,})['"]?`,
			Type:        "api_key",
			Severity:    "high",
			Description: "API key pattern detected",
		},
		{
			Name:        "Password",
			Pattern:     `(?i)(password|passwd|pwd)\s*[:=]\s*['"]?([^'"\s]{8,})['"]?`,
			Type:        "password",
			Severity:    "high",
			Description: "Password pattern detected",
		},
		{
			Name:        "Token",
			Pattern:     `(?i)(token|bearer)\s*[:=]\s*['"]?([a-zA-Z0-9._-]{20,})['"]?`,
			Type:        "token",
			Severity:    "high",
			Description: "Token pattern detected",
		},
		{
			Name:        "Secret Key",
			Pattern:     `(?i)(secret[_-]?key|secretkey)\s*[:=]\s*['"]?([a-zA-Z0-9_-]{20,})['"]?`,
			Type:        "secret_key",
			Severity:    "critical",
			Description: "Secret key pattern detected",
		},
		{
			Name:        "Database URL",
			Pattern:     `(?i)(database[_-]?url|db[_-]?url)\s*[:=]\s*['"]?([^'"\s]+)['"]?`,
			Type:        "database_url",
			Severity:    "high",
			Description: "Database URL pattern detected",
		},
	}
}

func (ss *SecretScanner) isLikelySecret(value string, patterns []SecretPattern) bool {
	for _, pattern := range patterns {
		regex, err := regexp.Compile(pattern.Pattern)
		if err != nil {
			continue
		}
		if regex.MatchString(value) {
			return true
		}
	}

	// Check entropy for high-entropy strings
	if ss.calculateEntropy(value) > 4.0 && len(value) > 16 {
		return true
	}

	return false
}

func (ss *SecretScanner) calculateEntropy(value string) float64 {
	if len(value) == 0 {
		return 0
	}

	freq := make(map[rune]int)
	for _, char := range value {
		freq[char]++
	}

	entropy := 0.0
	for _, count := range freq {
		p := float64(count) / float64(len(value))
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}

	return entropy
}

func (ss *SecretScanner) redactSecret(value string) string {
	if len(value) <= 8 {
		return "***"
	}
	return value[:4] + "***" + value[len(value)-4:]
}

func (ss *SecretScanner) isClusterWideImagePullSecret(secret corev1.Secret) bool {
	// Check if secret is used cluster-wide
	// This is a simplified check - in reality, you'd need to check all pods and service accounts
	return secret.Annotations["cluster-wide"] == "true"
}

func (ss *SecretScanner) extractVaultURL(value string) string {
	// Extract vault URL from configuration
	// This is a simplified extraction
	if strings.Contains(value, "vault") {
		return "https://vault.example.com"
	}
	return ""
}

// GenerateRandomSecret generates a random secret for testing
func (ss *SecretScanner) GenerateRandomSecret(length int) string {
	bytes := make([]byte, length)
	rand.Read(bytes)
	return base64.URLEncoding.EncodeToString(bytes)
}
