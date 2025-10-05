package k08_secrets

import (
	"context"
	"time"

	"k8s.io/client-go/kubernetes"
)

// SecretFinding represents a secrets management security finding
type SecretFinding struct {
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

// SecretSummary represents summary statistics for secrets findings
type SecretSummary struct {
	TotalFindings         int     `json:"totalFindings"`
	CriticalCount         int     `json:"criticalCount"`
	HighCount             int     `json:"highCount"`
	MediumCount           int     `json:"mediumCount"`
	LowCount              int     `json:"lowCount"`
	SecretScore           float64 `json:"secretScore"`
	RawSecretsFound       int     `json:"rawSecretsFound"`
	ConfigMapSecrets      int     `json:"configMapSecrets"`
	ExposedSecrets        int     `json:"exposedSecrets"`
	UnencryptedSecrets    int     `json:"unencryptedSecrets"`
	WeakImagePullSecrets  int     `json:"weakImagePullSecrets"`
	KMSEncryptionEnabled  bool    `json:"kmsEncryptionEnabled"`
	EtcdEncryptionEnabled bool    `json:"etcdEncryptionEnabled"`
}

// SecretScanner represents the secrets scanner
type SecretScanner struct {
	client    kubernetes.Interface
	namespace string
	ctx       context.Context
	labMode   bool
	confirm   bool
}

// SecretInfo represents information about a detected secret
type SecretInfo struct {
	Name          string            `json:"name"`
	Namespace     string            `json:"namespace"`
	Type          string            `json:"type"`
	Source        string            `json:"source"`
	Exposed       bool              `json:"exposed"`
	Encrypted     bool              `json:"encrypted"`
	RiskLevel     string            `json:"riskLevel"`
	Value         string            `json:"value,omitempty"` // Only populated in lab mode with confirm
	RedactedValue string            `json:"redactedValue"`
	Metadata      map[string]string `json:"metadata"`
	Usage         []SecretUsage     `json:"usage"`
}

// SecretUsage represents how a secret is being used
type SecretUsage struct {
	Resource    string            `json:"resource"`
	Namespace   string            `json:"namespace"`
	Type        string            `json:"type"`
	Environment string            `json:"environment"`
	Volume      string            `json:"volume,omitempty"`
	Metadata    map[string]string `json:"metadata"`
}

// ConfigMapSecret represents a secret found in a ConfigMap
type ConfigMapSecret struct {
	ConfigMapName string            `json:"configMapName"`
	Namespace     string            `json:"namespace"`
	Key           string            `json:"key"`
	Value         string            `json:"value,omitempty"` // Only populated in lab mode with confirm
	RedactedValue string            `json:"redactedValue"`
	Type          string            `json:"type"`
	RiskLevel     string            `json:"riskLevel"`
	Metadata      map[string]string `json:"metadata"`
}

// ImagePullSecret represents an image pull secret
type ImagePullSecret struct {
	Name      string            `json:"name"`
	Namespace string            `json:"namespace"`
	Type      string            `json:"type"`
	Registry  string            `json:"registry"`
	Scope     string            `json:"scope"`
	RiskLevel string            `json:"riskLevel"`
	Metadata  map[string]string `json:"metadata"`
}

// EtcdEncryption represents etcd encryption status
type EtcdEncryption struct {
	Enabled   bool              `json:"enabled"`
	Providers []string          `json:"providers"`
	Keys      []string          `json:"keys"`
	Metadata  map[string]string `json:"metadata"`
}

// KMSEncryption represents KMS encryption status
type KMSEncryption struct {
	Enabled  bool              `json:"enabled"`
	Provider string            `json:"provider"`
	KeyID    string            `json:"keyId"`
	Region   string            `json:"region"`
	Metadata map[string]string `json:"metadata"`
}

// VaultInfo represents external vault information
type VaultInfo struct {
	Name      string            `json:"name"`
	Type      string            `json:"type"`
	URL       string            `json:"url"`
	Exposed   bool              `json:"exposed"`
	RiskLevel string            `json:"riskLevel"`
	Metadata  map[string]string `json:"metadata"`
}

// SecretExfiltration represents a simulated secret exfiltration
type SecretExfiltration struct {
	SecretName  string            `json:"secretName"`
	Namespace   string            `json:"namespace"`
	Method      string            `json:"method"`
	Destination string            `json:"destination"`
	RiskLevel   string            `json:"riskLevel"`
	Description string            `json:"description"`
	Metadata    map[string]string `json:"metadata"`
	Timestamp   time.Time         `json:"timestamp"`
}

// SecretPattern represents a pattern for detecting secrets
type SecretPattern struct {
	Name        string `json:"name"`
	Pattern     string `json:"pattern"`
	Type        string `json:"type"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
}

// SecretReport represents the complete secrets report
type SecretReport struct {
	Findings          []SecretFinding      `json:"findings"`
	Summary           SecretSummary        `json:"summary"`
	Secrets           []SecretInfo         `json:"secrets"`
	ConfigMapSecrets  []ConfigMapSecret    `json:"configMapSecrets"`
	ImagePullSecrets  []ImagePullSecret    `json:"imagePullSecrets"`
	EtcdEncryption    EtcdEncryption       `json:"etcdEncryption"`
	KMSEncryption     KMSEncryption        `json:"kmsEncryption"`
	Vaults            []VaultInfo          `json:"vaults"`
	ExfiltrationTests []SecretExfiltration `json:"exfiltrationTests"`
	Recommendations   []string             `json:"recommendations"`
	GeneratedAt       time.Time            `json:"generatedAt"`
}
