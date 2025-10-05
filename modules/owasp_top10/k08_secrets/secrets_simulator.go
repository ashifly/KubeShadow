package k08_secrets

import (
	"fmt"
	"time"
)

// SimulateSecretExfiltration simulates secret exfiltration scenarios
func (ss *SecretScanner) SimulateSecretExfiltration() ([]SecretExfiltration, error) {
	var exfiltrations []SecretExfiltration

	// Only run in lab mode for safety
	if !ss.labMode {
		return exfiltrations, nil
	}

	// Simulate different exfiltration methods
	exfiltrations = append(exfiltrations, ss.simulateEnvironmentVariableExfiltration())
	exfiltrations = append(exfiltrations, ss.simulateConfigMapExfiltration())
	exfiltrations = append(exfiltrations, ss.simulateVolumeMountExfiltration())
	exfiltrations = append(exfiltrations, ss.simulateNetworkExfiltration())

	return exfiltrations, nil
}

// simulateEnvironmentVariableExfiltration simulates secret exfiltration via environment variables
func (ss *SecretScanner) simulateEnvironmentVariableExfiltration() SecretExfiltration {
	return SecretExfiltration{
		SecretName:  "database-password",
		Namespace:   "production",
		Method:      "environment-variable",
		Destination: "external-server.com:8080",
		RiskLevel:   "high",
		Description: "Simulated exfiltration of database password from environment variable",
		Metadata: map[string]string{
			"exfiltration_method": "env_var",
			"secret_type":         "password",
			"target_pod":          "web-app-123",
		},
		Timestamp: time.Now(),
	}
}

// simulateConfigMapExfiltration simulates secret exfiltration via ConfigMap
func (ss *SecretScanner) simulateConfigMapExfiltration() SecretExfiltration {
	return SecretExfiltration{
		SecretName:  "api-key",
		Namespace:   "default",
		Method:      "configmap-access",
		Destination: "attacker-controlled-server.com",
		RiskLevel:   "critical",
		Description: "Simulated exfiltration of API key from ConfigMap",
		Metadata: map[string]string{
			"exfiltration_method": "configmap",
			"secret_type":         "api_key",
			"configmap_name":      "app-config",
		},
		Timestamp: time.Now(),
	}
}

// simulateVolumeMountExfiltration simulates secret exfiltration via volume mount
func (ss *SecretScanner) simulateVolumeMountExfiltration() SecretExfiltration {
	return SecretExfiltration{
		SecretName:  "tls-certificate",
		Namespace:   "kube-system",
		Method:      "volume-mount",
		Destination: "malicious-container.io",
		RiskLevel:   "high",
		Description: "Simulated exfiltration of TLS certificate from volume mount",
		Metadata: map[string]string{
			"exfiltration_method": "volume_mount",
			"secret_type":         "certificate",
			"volume_name":         "tls-certs",
		},
		Timestamp: time.Now(),
	}
}

// simulateNetworkExfiltration simulates secret exfiltration via network
func (ss *SecretScanner) simulateNetworkExfiltration() SecretExfiltration {
	return SecretExfiltration{
		SecretName:  "database-credentials",
		Namespace:   "backend",
		Method:      "network-exfiltration",
		Destination: "exfil-server.example.com:443",
		RiskLevel:   "critical",
		Description: "Simulated exfiltration of database credentials via network",
		Metadata: map[string]string{
			"exfiltration_method": "network",
			"secret_type":         "credentials",
			"protocol":            "https",
		},
		Timestamp: time.Now(),
	}
}

// GenerateSecretRemediationTemplates generates remediation templates for secret management
func (ss *SecretScanner) GenerateSecretRemediationTemplates() []string {
	var templates []string

	// Secret resource template
	templates = append(templates, `apiVersion: v1
kind: Secret
metadata:
  name: database-credentials
  namespace: production
type: Opaque
data:
  username: <base64-encoded-username>
  password: <base64-encoded-password>`)

	// KMS encryption template
	templates = append(templates, `apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
- resources:
  - secrets
  providers:
  - kms:
      name: kms-provider
      endpoint: unix:///tmp/kms.socket
      cachesize: 100
  - identity: {}`)

	// Vault integration template
	templates = append(templates, `apiVersion: v1
kind: Secret
metadata:
  name: vault-token
  namespace: vault
  annotations:
    vault.hashicorp.com/role: "kubernetes"
type: Opaque
data:
  token: <vault-token>`)

	// Secretless pattern template
	templates = append(templates, `apiVersion: apps/v1
kind: Deployment
metadata:
  name: secretless-proxy
spec:
  template:
    spec:
      containers:
      - name: secretless
        image: cyberark/secretless-broker:latest
        env:
        - name: SECRETLESS_CREDENTIALS
          value: "database://vault://secret/db#username,database://vault://secret/db#password"`)

	return templates
}

// GenerateKMSConfiguration generates KMS configuration templates
func (ss *SecretScanner) GenerateKMSConfiguration() []string {
	var configs []string

	// AWS KMS configuration
	configs = append(configs, `apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
- resources:
  - secrets
  providers:
  - kms:
      name: aws-kms
      endpoint: unix:///tmp/kms.socket
      cachesize: 100
      timeout: 3s
  - identity: {}`)

	// Azure Key Vault configuration
	configs = append(configs, `apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
- resources:
  - secrets
  providers:
  - kms:
      name: azure-kv
      endpoint: unix:///tmp/kms.socket
      cachesize: 100
  - identity: {}`)

	// GCP KMS configuration
	configs = append(configs, `apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
- resources:
  - secrets
  providers:
  - kms:
      name: gcp-kms
      endpoint: unix:///tmp/kms.socket
      cachesize: 100
  - identity: {}`)

	return configs
}

// GenerateSecretlessPatterns generates secretless pattern examples
func (ss *SecretScanner) GenerateSecretlessPatterns() []string {
	var patterns []string

	// Vault Agent pattern
	patterns = append(patterns, `apiVersion: apps/v1
kind: Deployment
metadata:
  name: vault-agent
spec:
  template:
    spec:
      containers:
      - name: vault-agent
        image: vault:latest
        command: ["vault", "agent", "-config=/vault/config/agent.hcl"]
        volumeMounts:
        - name: vault-config
          mountPath: /vault/config
      volumes:
      - name: vault-config
        configMap:
          name: vault-agent-config`)

	// External Secrets Operator pattern
	patterns = append(patterns, `apiVersion: external-secrets.io/v1beta1
kind: SecretStore
metadata:
  name: vault-backend
spec:
  provider:
    vault:
      server: "https://vault.example.com"
      path: "secret"
      version: "v2"
      auth:
        kubernetes:
          mountPath: "kubernetes"
          role: "kubernetes"`)

	// Sealed Secrets pattern
	patterns = append(patterns, `apiVersion: bitnami.com/v1alpha1
kind: SealedSecret
metadata:
  name: database-credentials
  namespace: production
spec:
  encryptedData:
    username: AgBy3i4OJSWK+PiTySYZZA9rO43cGDEQAx...
    password: AgBy3i4OJSWK+PiTySYZZA9rO43cGDEQAx...
  template:
    metadata:
      name: database-credentials
      namespace: production
    type: Opaque`)

	return patterns
}

// TestSecretDetection tests secret detection capabilities
func (ss *SecretScanner) TestSecretDetection() ([]SecretFinding, error) {
	var findings []SecretFinding

	// Only run in lab mode for safety
	if !ss.labMode {
		return findings, nil
	}

	// Test secret patterns
	patterns := ss.getSecretPatterns()
	testValues := []string{
		"password=secret123",
		"api_key=sk-1234567890abcdef",
		"token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
		"database_url=postgresql://user:pass@localhost:5432/db",
		"secret_key=abcdef1234567890",
	}

	for i, value := range testValues {
		if ss.isLikelySecret(value, patterns) {
			findings = append(findings, SecretFinding{
				ID:          fmt.Sprintf("test-secret-%d", i+1),
				Type:        "test-detection",
				Severity:    "medium",
				Title:       "Secret Detection Test",
				Description: fmt.Sprintf("Test secret pattern detected: %s", ss.redactSecret(value)),
				Resource:    "test",
				Namespace:   "test",
				RiskScore:   5.0,
				Remediation: "This is a test detection - implement proper secret management.",
				Timestamp:   time.Now(),
				Metadata: map[string]string{
					"test_value": ss.redactSecret(value),
					"test_type":  "pattern_detection",
				},
			})
		}
	}

	return findings, nil
}

// GenerateSecretScanningRules generates rules for secret scanning
func (ss *SecretScanner) GenerateSecretScanningRules() []string {
	var rules []string

	// GitLeaks configuration
	rules = append(rules, `[rules]
[[rules.aws-access-key]]
description = "AWS Access Key"
regex = '''AKIA[0-9A-Z]{16}'''
tags = ["key", "AWS"]

[[rules.aws-secret-key]]
description = "AWS Secret Key"
regex = '''[A-Za-z0-9/+=]{40}'''
tags = ["key", "AWS"]

[[rules.github-token]]
description = "GitHub Token"
regex = '''ghp_[0-9a-zA-Z]{36}'''
tags = ["key", "GitHub"]`)

	// TruffleHog configuration
	rules = append(rules, `detectors:
  - name: "AWS Access Key"
    regex: "AKIA[0-9A-Z]{16}"
    confidence: "high"
  - name: "GitHub Token"
    regex: "ghp_[0-9a-zA-Z]{36}"
    confidence: "high"
  - name: "API Key"
    regex: "(?i)(api[_-]?key|apikey)\\s*[:=]\\s*['\"]?([a-zA-Z0-9_-]{20,})['\"]?"
    confidence: "medium"`)

	return rules
}

// SimulateSecretRotation simulates secret rotation scenarios
func (ss *SecretScanner) SimulateSecretRotation() ([]SecretFinding, error) {
	var findings []SecretFinding

	// Only run in lab mode for safety
	if !ss.labMode {
		return findings, nil
	}

	// Simulate old secrets that need rotation
	oldSecrets := []string{
		"database-password-2023",
		"api-key-v1",
		"tls-certificate-expired",
		"jwt-secret-old",
	}

	for i, secretName := range oldSecrets {
		findings = append(findings, SecretFinding{
			ID:          fmt.Sprintf("rotation-%d", i+1),
			Type:        "secret-rotation",
			Severity:    "medium",
			Title:       "Secret Rotation Required",
			Description: fmt.Sprintf("Secret %s needs rotation due to age or expiration.", secretName),
			Resource:    fmt.Sprintf("secret/%s", secretName),
			Namespace:   "production",
			RiskScore:   6.0,
			Remediation: "Implement automated secret rotation for this secret.",
			Timestamp:   time.Now(),
			Metadata: map[string]string{
				"secret_name":     secretName,
				"rotation_reason": "age",
			},
		})
	}

	return findings, nil
}
