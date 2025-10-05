package rbac

import (
	"context"
	"time"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/client-go/kubernetes"
)

// RBACGraph represents the complete RBAC graph
type RBACGraph struct {
	Nodes []GraphNode `json:"nodes"`
	Edges []GraphEdge `json:"edges"`
}

// GraphNode represents a node in the RBAC graph
type GraphNode struct {
	ID        string                 `json:"id"`
	Type      string                 `json:"type"` // "subject", "resource", "verb"
	Name      string                 `json:"name"`
	Namespace string                 `json:"namespace,omitempty"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// GraphEdge represents an edge in the RBAC graph
type GraphEdge struct {
	From     string `json:"from"`
	To       string `json:"to"`
	Verb     string `json:"verb"`
	Resource string `json:"resource"`
	Weight   int    `json:"weight"` // For path scoring
}

// EscalationPath represents a privilege escalation path
type EscalationPath struct {
	Subject     string         `json:"subject"`
	Target      ResourceAction `json:"target"`
	Steps       []PathStep     `json:"steps"`
	TotalWeight int            `json:"totalWeight"`
	RiskLevel   string         `json:"riskLevel"`
}

// PathStep represents a single step in an escalation path
type PathStep struct {
	From     string `json:"from"`
	To       string `json:"to"`
	Action   string `json:"action"`
	Resource string `json:"resource"`
	Weight   int    `json:"weight"`
}

// ResourceAction represents a target resource and action
type ResourceAction struct {
	Resource  string `json:"resource"`
	Verb      string `json:"verb"`
	Namespace string `json:"namespace,omitempty"`
}

// RBACFinding represents a security finding in RBAC configuration
type RBACFinding struct {
	Subject         string           `json:"subject"`
	SubjectType     string           `json:"subjectType"` // "ServiceAccount", "User", "Group"
	Namespace       string           `json:"namespace"`
	Role            string           `json:"role"`
	RoleType        string           `json:"roleType"` // "Role", "ClusterRole"
	Permissions     []Permission     `json:"permissions"`
	RiskScore       float64          `json:"riskScore"`
	Severity        string           `json:"severity"`
	EscalationPaths []EscalationPath `json:"escalationPaths,omitempty"`
	Remediation     Remediation      `json:"remediation"`
}

// Permission represents a single permission
type Permission struct {
	Resource string   `json:"resource"`
	Verbs    []string `json:"verbs"`
	APIGroup string   `json:"apiGroup,omitempty"`
}

// Remediation represents remediation suggestions
type Remediation struct {
	Description    string   `json:"description"`
	LeastPrivilege []string `json:"leastPrivilege"`
	FalcoRules     []string `json:"falcoRules"`
	KubectlApply   string   `json:"kubectlApply"`
}

// RBACScanner represents the RBAC scanner
type RBACScanner struct {
	client *kubernetes.Clientset
	ctx    context.Context
}

// RBACData represents collected RBAC data
type RBACData struct {
	Roles               []rbacv1.Role               `json:"roles"`
	ClusterRoles        []rbacv1.ClusterRole        `json:"clusterRoles"`
	RoleBindings        []rbacv1.RoleBinding        `json:"roleBindings"`
	ClusterRoleBindings []rbacv1.ClusterRoleBinding `json:"clusterRoleBindings"`
	ServiceAccounts     []corev1.ServiceAccount     `json:"serviceAccounts"`
	CollectedAt         time.Time                   `json:"collectedAt"`
}

// RiskyBinding represents a risky RBAC binding
type RiskyBinding struct {
	Subject     string  `json:"subject"`
	Role        string  `json:"role"`
	RiskScore   float64 `json:"riskScore"`
	Reason      string  `json:"reason"`
	Remediation string  `json:"remediation"`
}
