package k06_auth

import (
	"context"
	"time"

	"k8s.io/client-go/kubernetes"
)

// AuthFinding represents an authentication security finding
type AuthFinding struct {
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

// AuthSummary represents summary statistics for authentication findings
type AuthSummary struct {
	TotalFindings      int     `json:"totalFindings"`
	CriticalCount      int     `json:"criticalCount"`
	HighCount          int     `json:"highCount"`
	MediumCount        int     `json:"mediumCount"`
	LowCount           int     `json:"lowCount"`
	AuthScore          float64 `json:"authScore"`
	AnonymousAccess    bool    `json:"anonymousAccess"`
	WeakAuthMethods    int     `json:"weakAuthMethods"`
	ExposedCredentials int     `json:"exposedCredentials"`
	PublicEndpoints    int     `json:"publicEndpoints"`
	TokenAge           int     `json:"tokenAge"`
	CredentialRotation bool    `json:"credentialRotation"`
}

// AuthScanner represents the authentication scanner
type AuthScanner struct {
	client    kubernetes.Interface
	namespace string
	ctx       context.Context
	labMode   bool
}

// APIServerConfig represents Kubernetes API server configuration
type APIServerConfig struct {
	AnonymousAuth    bool              `json:"anonymousAuth"`
	BasicAuth        bool              `json:"basicAuth"`
	TokenAuth        bool              `json:"tokenAuth"`
	CertAuth         bool              `json:"certAuth"`
	OIDCAuth         bool              `json:"oidcAuth"`
	RBACEnabled      bool              `json:"rbacEnabled"`
	AdmissionPlugins []string          `json:"admissionPlugins"`
	AuditLogging     bool              `json:"auditLogging"`
	SecurePort       int               `json:"securePort"`
	InsecurePort     int               `json:"insecurePort"`
	BindAddress      string            `json:"bindAddress"`
	Metadata         map[string]string `json:"metadata"`
}

// KubeConfigInfo represents kubeconfig file information
type KubeConfigInfo struct {
	Path        string            `json:"path"`
	Context     string            `json:"context"`
	Server      string            `json:"server"`
	AuthMethod  string            `json:"authMethod"`
	User        string            `json:"user"`
	Namespace   string            `json:"namespace"`
	Expires     time.Time         `json:"expires"`
	Permissions []string          `json:"permissions"`
	Metadata    map[string]string `json:"metadata"`
	Exposed     bool              `json:"exposed"`
	RiskLevel   string            `json:"riskLevel"`
}

// TokenInfo represents service account token information
type TokenInfo struct {
	Name           string            `json:"name"`
	Namespace      string            `json:"namespace"`
	ServiceAccount string            `json:"serviceAccount"`
	Expires        time.Time         `json:"expires"`
	Age            time.Duration     `json:"age"`
	Permissions    []string          `json:"permissions"`
	Exposed        bool              `json:"exposed"`
	Location       string            `json:"location"`
	Metadata       map[string]string `json:"metadata"`
	RiskLevel      string            `json:"riskLevel"`
}

// PublicEndpoint represents a publicly accessible endpoint
type PublicEndpoint struct {
	URL          string            `json:"url"`
	Type         string            `json:"type"`
	AuthRequired bool              `json:"authRequired"`
	AuthMethod   string            `json:"authMethod"`
	Exposed      bool              `json:"exposed"`
	RiskLevel    string            `json:"riskLevel"`
	Metadata     map[string]string `json:"metadata"`
}

// AuthTest represents an authentication test result
type AuthTest struct {
	TestName    string            `json:"testName"`
	Description string            `json:"description"`
	Success     bool              `json:"success"`
	RiskLevel   string            `json:"riskLevel"`
	Details     string            `json:"details"`
	Metadata    map[string]string `json:"metadata"`
	Timestamp   time.Time         `json:"timestamp"`
}

// AuthReport represents the complete authentication report
type AuthReport struct {
	Findings        []AuthFinding    `json:"findings"`
	Summary         AuthSummary      `json:"summary"`
	APIServerConfig APIServerConfig  `json:"apiServerConfig"`
	KubeConfigs     []KubeConfigInfo `json:"kubeConfigs"`
	Tokens          []TokenInfo      `json:"tokens"`
	PublicEndpoints []PublicEndpoint `json:"publicEndpoints"`
	AuthTests       []AuthTest       `json:"authTests"`
	Recommendations []string         `json:"recommendations"`
	GeneratedAt     time.Time        `json:"generatedAt"`
}
