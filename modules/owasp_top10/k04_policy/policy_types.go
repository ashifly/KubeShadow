package policy

import (
	"context"
	"time"

	"k8s.io/client-go/kubernetes"
)

// PolicyEnforcement represents the state of policy enforcement in the cluster
type PolicyEnforcement struct {
	Gatekeeper        *GatekeeperInfo `json:"gatekeeper,omitempty"`
	OPA               *OPAInfo        `json:"opa,omitempty"`
	Kyverno           *KyvernoInfo    `json:"kyverno,omitempty"`
	AdmissionWebhooks []WebhookInfo   `json:"admissionWebhooks"`
	PolicyCoverage    PolicyCoverage  `json:"policyCoverage"`
	ScanTime          time.Time       `json:"scanTime"`
}

// GatekeeperInfo represents Gatekeeper installation and configuration
type GatekeeperInfo struct {
	Installed           bool                     `json:"installed"`
	Version             string                   `json:"version,omitempty"`
	Constraints         []ConstraintInfo         `json:"constraints"`
	ConstraintTemplates []ConstraintTemplateInfo `json:"constraintTemplates"`
	Enforcement         string                   `json:"enforcement"` // "warn", "deny", "dryrun"
}

// OPAInfo represents OPA installation and configuration
type OPAInfo struct {
	Installed bool        `json:"installed"`
	Version   string      `json:"version,omitempty"`
	Policies  []OPAPolicy `json:"policies"`
	ConfigMap string      `json:"configMap,omitempty"`
}

// KyvernoInfo represents Kyverno installation and configuration
type KyvernoInfo struct {
	Installed       bool            `json:"installed"`
	Version         string          `json:"version,omitempty"`
	Policies        []KyvernoPolicy `json:"policies"`
	ClusterPolicies []KyvernoPolicy `json:"clusterPolicies"`
}

// ConstraintInfo represents a Gatekeeper constraint
type ConstraintInfo struct {
	Name        string                 `json:"name"`
	Kind        string                 `json:"kind"`
	Namespace   string                 `json:"namespace"`
	Enforcement string                 `json:"enforcement"`
	Violations  int                    `json:"violations"`
	Match       map[string]interface{} `json:"match"`
	Parameters  map[string]interface{} `json:"parameters"`
}

// ConstraintTemplateInfo represents a Gatekeeper constraint template
type ConstraintTemplateInfo struct {
	Name   string `json:"name"`
	Kind   string `json:"kind"`
	CRD    string `json:"crd"`
	Target string `json:"target"`
	Rego   string `json:"rego"`
}

// OPAPolicy represents an OPA policy
type OPAPolicy struct {
	Name        string `json:"name"`
	Namespace   string `json:"namespace"`
	Rego        string `json:"rego"`
	Enabled     bool   `json:"enabled"`
	Description string `json:"description"`
}

// KyvernoPolicy represents a Kyverno policy
type KyvernoPolicy struct {
	Name       string        `json:"name"`
	Namespace  string        `json:"namespace"`
	Type       string        `json:"type"` // "Policy" or "ClusterPolicy"
	Rules      []KyvernoRule `json:"rules"`
	Validation string        `json:"validation"` // "enforce", "audit", "warn"
	Background bool          `json:"background"`
}

// KyvernoRule represents a Kyverno policy rule
type KyvernoRule struct {
	Name     string                 `json:"name"`
	Match    map[string]interface{} `json:"match"`
	Exclude  map[string]interface{} `json:"exclude,omitempty"`
	Validate map[string]interface{} `json:"validate,omitempty"`
	Mutate   map[string]interface{} `json:"mutate,omitempty"`
	Generate map[string]interface{} `json:"generate,omitempty"`
}

// WebhookInfo represents an admission webhook
type WebhookInfo struct {
	Name          string        `json:"name"`
	Namespace     string        `json:"namespace"`
	Type          string        `json:"type"` // "ValidatingAdmissionWebhook" or "MutatingAdmissionWebhook"
	Service       string        `json:"service"`
	Rules         []WebhookRule `json:"rules"`
	FailurePolicy string        `json:"failurePolicy"`
	SideEffects   string        `json:"sideEffects"`
	Enabled       bool          `json:"enabled"`
}

// WebhookRule represents a webhook rule
type WebhookRule struct {
	Operations  []string `json:"operations"`
	APIGroups   []string `json:"apiGroups"`
	APIVersions []string `json:"apiVersions"`
	Resources   []string `json:"resources"`
	Scope       string   `json:"scope"`
}

// PolicyCoverage represents policy coverage analysis
type PolicyCoverage struct {
	Namespaces       []NamespaceCoverage `json:"namespaces"`
	ResourceTypes    []ResourceCoverage  `json:"resourceTypes"`
	StandardPolicies []StandardPolicy    `json:"standardPolicies"`
	CoverageScore    float64             `json:"coverageScore"`
	Recommendations  []Recommendation    `json:"recommendations"`
}

// NamespaceCoverage represents policy coverage for a namespace
type NamespaceCoverage struct {
	Name            string            `json:"name"`
	Labels          map[string]string `json:"labels"`
	Policies        []string          `json:"policies"`
	Exemptions      []string          `json:"exemptions"`
	CoverageScore   float64           `json:"coverageScore"`
	MissingPolicies []string          `json:"missingPolicies"`
	RiskLevel       string            `json:"riskLevel"`
}

// ResourceCoverage represents policy coverage for a resource type
type ResourceCoverage struct {
	ResourceType    string   `json:"resourceType"`
	APIGroup        string   `json:"apiGroup"`
	Policies        []string `json:"policies"`
	CoverageScore   float64  `json:"coverageScore"`
	MissingPolicies []string `json:"missingPolicies"`
}

// StandardPolicy represents a recommended standard policy
type StandardPolicy struct {
	Name           string `json:"name"`
	Description    string `json:"description"`
	Category       string `json:"category"`
	Severity       string `json:"severity"`
	Implementation string `json:"implementation"` // "Gatekeeper", "OPA", "Kyverno"
	Manifest       string `json:"manifest"`
	Priority       int    `json:"priority"`
}

// Recommendation represents a policy recommendation
type Recommendation struct {
	Type           string `json:"type"`
	Description    string `json:"description"`
	Priority       string `json:"priority"`
	Implementation string `json:"implementation"`
	Manifest       string `json:"manifest"`
}

// PolicyFinding represents a policy security finding
type PolicyFinding struct {
	Namespace      string  `json:"namespace"`
	ResourceType   string  `json:"resourceType"`
	ResourceName   string  `json:"resourceName"`
	PolicyGap      string  `json:"policyGap"`
	Severity       string  `json:"severity"`
	RiskScore      float64 `json:"riskScore"`
	Description    string  `json:"description"`
	Recommendation string  `json:"recommendation"`
	StandardPolicy string  `json:"standardPolicy"`
}

// PolicyScanner represents the policy scanner
type PolicyScanner struct {
	client    *kubernetes.Clientset
	namespace string
	ctx       context.Context
}

// PolicyEvaluation represents the result of policy evaluation
type PolicyEvaluation struct {
	Manifest          string            `json:"manifest"`
	Violations        []PolicyViolation `json:"violations"`
	Allowed           bool              `json:"allowed"`
	EnforcementAction string            `json:"enforcementAction"`
	PolicyEngine      string            `json:"policyEngine"`
}

// PolicyViolation represents a policy violation
type PolicyViolation struct {
	Policy   string `json:"policy"`
	Rule     string `json:"rule"`
	Message  string `json:"message"`
	Severity string `json:"severity"`
	Resource string `json:"resource"`
	Field    string `json:"field,omitempty"`
}
