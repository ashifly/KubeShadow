package k09_components

import (
	"context"
	"time"

	"k8s.io/client-go/kubernetes"
)

// ComponentFinding represents a cluster component security finding
type ComponentFinding struct {
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

// ComponentSummary represents summary statistics for component findings
type ComponentSummary struct {
	TotalFindings         int     `json:"totalFindings"`
	CriticalCount         int     `json:"criticalCount"`
	HighCount             int     `json:"highCount"`
	MediumCount           int     `json:"mediumCount"`
	LowCount              int     `json:"lowCount"`
	ComponentScore        float64 `json:"componentScore"`
	WebhookCount          int     `json:"webhookCount"`
	MisconfiguredWebhooks int     `json:"misconfiguredWebhooks"`
	CRDCount              int     `json:"crdCount"`
	RiskyCRDs             int     `json:"riskyCRDs"`
	OutdatedControllers   int     `json:"outdatedControllers"`
	AdmissionWebhooks     int     `json:"admissionWebhooks"`
	MutatingWebhooks      int     `json:"mutatingWebhooks"`
	ValidatingWebhooks    int     `json:"validatingWebhooks"`
}

// ComponentScanner represents the component scanner
type ComponentScanner struct {
	client    kubernetes.Interface
	namespace string
	ctx       context.Context
	labMode   bool
}

// WebhookInfo represents information about a webhook configuration
type WebhookInfo struct {
	Name                    string             `json:"name"`
	Namespace               string             `json:"namespace"`
	Type                    string             `json:"type"`
	ServiceName             string             `json:"serviceName"`
	ServiceNamespace        string             `json:"serviceNamespace"`
	ServicePath             string             `json:"servicePath"`
	CABundle                string             `json:"caBundle"`
	FailurePolicy           string             `json:"failurePolicy"`
	AdmissionReviewVersions []string           `json:"admissionReviewVersions"`
	Rules                   []WebhookRule      `json:"rules"`
	NamespaceSelector       *NamespaceSelector `json:"namespaceSelector,omitempty"`
	ObjectSelector          *ObjectSelector    `json:"objectSelector,omitempty"`
	RiskLevel               string             `json:"riskLevel"`
	Metadata                map[string]string  `json:"metadata"`
}

// WebhookRule represents a webhook rule
type WebhookRule struct {
	APIGroups   []string `json:"apiGroups"`
	APIVersions []string `json:"apiVersions"`
	Resources   []string `json:"resources"`
	Operations  []string `json:"operations"`
	Scope       string   `json:"scope"`
}

// NamespaceSelector represents namespace selector criteria
type NamespaceSelector struct {
	MatchLabels      map[string]string `json:"matchLabels"`
	MatchExpressions []MatchExpression `json:"matchExpressions,omitempty"`
}

// ObjectSelector represents object selector criteria
type ObjectSelector struct {
	MatchLabels      map[string]string `json:"matchLabels"`
	MatchExpressions []MatchExpression `json:"matchExpressions,omitempty"`
}

// MatchExpression represents a match expression
type MatchExpression struct {
	Key      string   `json:"key"`
	Operator string   `json:"operator"`
	Values   []string `json:"values"`
}

// CRDInfo represents information about a Custom Resource Definition
type CRDInfo struct {
	Name         string            `json:"name"`
	Group        string            `json:"group"`
	Version      string            `json:"version"`
	Scope        string            `json:"scope"`
	Names        CRDNames          `json:"names"`
	Validation   *CRDValidation    `json:"validation,omitempty"`
	Subresources *CRDSubresources  `json:"subresources,omitempty"`
	RiskLevel    string            `json:"riskLevel"`
	Metadata     map[string]string `json:"metadata"`
}

// CRDNames represents CRD names
type CRDNames struct {
	Plural     string   `json:"plural"`
	Singular   string   `json:"singular"`
	ShortNames []string `json:"shortNames"`
	Kind       string   `json:"kind"`
	ListKind   string   `json:"listKind"`
}

// CRDValidation represents CRD validation schema
type CRDValidation struct {
	OpenAPIV3Schema map[string]interface{} `json:"openAPIV3Schema"`
}

// CRDSubresources represents CRD subresources
type CRDSubresources struct {
	Status *CRDStatus `json:"status,omitempty"`
	Scale  *CRDScale  `json:"scale,omitempty"`
}

// CRDStatus represents CRD status subresource
type CRDStatus struct{}

// CRDScale represents CRD scale subresource
type CRDScale struct {
	SpecReplicasPath   string `json:"specReplicasPath"`
	StatusReplicasPath string `json:"statusReplicasPath"`
	LabelSelectorPath  string `json:"labelSelectorPath"`
}

// ControllerInfo represents information about a controller
type ControllerInfo struct {
	Name      string            `json:"name"`
	Namespace string            `json:"namespace"`
	Type      string            `json:"type"`
	Version   string            `json:"version"`
	Image     string            `json:"image"`
	Outdated  bool              `json:"outdated"`
	RiskLevel string            `json:"riskLevel"`
	Metadata  map[string]string `json:"metadata"`
}

// WebhookAdmissionTest represents a webhook admission test
type WebhookAdmissionTest struct {
	TestName    string            `json:"testName"`
	Description string            `json:"description"`
	WebhookName string            `json:"webhookName"`
	Resource    string            `json:"resource"`
	Operation   string            `json:"operation"`
	Success     bool              `json:"success"`
	Mutated     bool              `json:"mutated"`
	Error       string            `json:"error"`
	Metadata    map[string]string `json:"metadata"`
	Timestamp   time.Time         `json:"timestamp"`
}

// WebhookRisk represents a webhook risk assessment
type WebhookRisk struct {
	WebhookName     string            `json:"webhookName"`
	RiskLevel       string            `json:"riskLevel"`
	RiskScore       float64           `json:"riskScore"`
	Issues          []string          `json:"issues"`
	Recommendations []string          `json:"recommendations"`
	Metadata        map[string]string `json:"metadata"`
}

// ComponentReport represents the complete component report
type ComponentReport struct {
	Findings        []ComponentFinding     `json:"findings"`
	Summary         ComponentSummary       `json:"summary"`
	Webhooks        []WebhookInfo          `json:"webhooks"`
	CRDs            []CRDInfo              `json:"crdInfos"`
	Controllers     []ControllerInfo       `json:"controllers"`
	AdmissionTests  []WebhookAdmissionTest `json:"admissionTests"`
	WebhookRisks    []WebhookRisk          `json:"webhookRisks"`
	Recommendations []string               `json:"recommendations"`
	GeneratedAt     time.Time              `json:"generatedAt"`
}
