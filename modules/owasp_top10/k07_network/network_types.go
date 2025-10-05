package k07_network

import (
	"context"
	"time"

	"k8s.io/client-go/kubernetes"
)

// NetworkFinding represents a network security finding
type NetworkFinding struct {
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

// NetworkSummary represents summary statistics for network findings
type NetworkSummary struct {
	TotalFindings         int     `json:"totalFindings"`
	CriticalCount         int     `json:"criticalCount"`
	HighCount             int     `json:"highCount"`
	MediumCount           int     `json:"mediumCount"`
	LowCount              int     `json:"lowCount"`
	NetworkScore          float64 `json:"networkScore"`
	NetworkPoliciesCount  int     `json:"networkPoliciesCount"`
	HostNetworkPods       int     `json:"hostNetworkPods"`
	PublicServices        int     `json:"publicServices"`
	UnprotectedNamespaces int     `json:"unprotectedNamespaces"`
	BlastRadius           int     `json:"blastRadius"`
	CNIProvider           string  `json:"cniProvider"`
	DefaultDenyEnabled    bool    `json:"defaultDenyEnabled"`
}

// NetworkScanner represents the network scanner
type NetworkScanner struct {
	client    kubernetes.Interface
	namespace string
	ctx       context.Context
	labMode   bool
}

// NetworkPolicyInfo represents NetworkPolicy information
type NetworkPolicyInfo struct {
	Name        string            `json:"name"`
	Namespace   string            `json:"namespace"`
	Type        string            `json:"type"`
	Enabled     bool              `json:"enabled"`
	Rules       []NetworkRule     `json:"rules"`
	PodSelector map[string]string `json:"podSelector"`
	Metadata    map[string]string `json:"metadata"`
}

// NetworkRule represents a network policy rule
type NetworkRule struct {
	Direction string            `json:"direction"`
	Protocol  string            `json:"protocol"`
	Port      int               `json:"port"`
	Source    NetworkSelector   `json:"source"`
	Target    NetworkSelector   `json:"target"`
	Action    string            `json:"action"`
	Metadata  map[string]string `json:"metadata"`
}

// NetworkSelector represents network selector criteria
type NetworkSelector struct {
	PodSelector       map[string]string `json:"podSelector"`
	NamespaceSelector map[string]string `json:"namespaceSelector"`
	IPBlock           string            `json:"ipBlock"`
	Ports             []int             `json:"ports"`
}

// ServiceInfo represents service network information
type ServiceInfo struct {
	Name       string            `json:"name"`
	Namespace  string            `json:"namespace"`
	Type       string            `json:"type"`
	ClusterIP  string            `json:"clusterIP"`
	ExternalIP string            `json:"externalIP"`
	Ports      []ServicePort     `json:"ports"`
	Public     bool              `json:"public"`
	Exposed    bool              `json:"exposed"`
	Metadata   map[string]string `json:"metadata"`
	RiskLevel  string            `json:"riskLevel"`
}

// ServicePort represents a service port
type ServicePort struct {
	Name       string `json:"name"`
	Port       int    `json:"port"`
	TargetPort int    `json:"targetPort"`
	Protocol   string `json:"protocol"`
	NodePort   int    `json:"nodePort"`
}

// PodNetworkInfo represents pod network information
type PodNetworkInfo struct {
	Name        string            `json:"name"`
	Namespace   string            `json:"namespace"`
	HostNetwork bool              `json:"hostNetwork"`
	HostPID     bool              `json:"hostPID"`
	HostIPC     bool              `json:"hostIPC"`
	IP          string            `json:"ip"`
	HostIP      string            `json:"hostIP"`
	Labels      map[string]string `json:"labels"`
	Metadata    map[string]string `json:"metadata"`
	RiskLevel   string            `json:"riskLevel"`
}

// ConnectivityTest represents a network connectivity test
type ConnectivityTest struct {
	TestName    string            `json:"testName"`
	Description string            `json:"description"`
	Source      string            `json:"source"`
	Target      string            `json:"target"`
	Protocol    string            `json:"protocol"`
	Port        int               `json:"port"`
	Success     bool              `json:"success"`
	Latency     time.Duration     `json:"latency"`
	Error       string            `json:"error"`
	Metadata    map[string]string `json:"metadata"`
	Timestamp   time.Time         `json:"timestamp"`
}

// BlastRadius represents the blast radius analysis
type BlastRadius struct {
	PodName           string            `json:"podName"`
	Namespace         string            `json:"namespace"`
	ReachablePods     int               `json:"reachablePods"`
	ReachableServices int               `json:"reachableServices"`
	RiskLevel         string            `json:"riskLevel"`
	Connections       []Connection      `json:"connections"`
	Metadata          map[string]string `json:"metadata"`
}

// Connection represents a network connection
type Connection struct {
	Source   string `json:"source"`
	Target   string `json:"target"`
	Protocol string `json:"protocol"`
	Port     int    `json:"port"`
	Allowed  bool   `json:"allowed"`
	Blocked  bool   `json:"blocked"`
	Reason   string `json:"reason"`
}

// CNIInfo represents CNI configuration information
type CNIInfo struct {
	Provider string            `json:"provider"`
	Version  string            `json:"version"`
	Config   map[string]string `json:"config"`
	Features []string          `json:"features"`
	Metadata map[string]string `json:"metadata"`
}

// NetworkMatrix represents the network policy matrix
type NetworkMatrix struct {
	Namespaces []string               `json:"namespaces"`
	Pods       []string               `json:"pods"`
	Services   []string               `json:"services"`
	Flows      []NetworkFlow          `json:"flows"`
	Metadata   map[string]interface{} `json:"metadata"`
}

// NetworkFlow represents a network flow
type NetworkFlow struct {
	Source   string `json:"source"`
	Target   string `json:"target"`
	Protocol string `json:"protocol"`
	Port     int    `json:"port"`
	Allowed  bool   `json:"allowed"`
	Policy   string `json:"policy"`
	Reason   string `json:"reason"`
}

// NetworkReport represents the complete network report
type NetworkReport struct {
	Findings          []NetworkFinding    `json:"findings"`
	Summary           NetworkSummary      `json:"summary"`
	NetworkPolicies   []NetworkPolicyInfo `json:"networkPolicies"`
	Services          []ServiceInfo       `json:"services"`
	Pods              []PodNetworkInfo    `json:"pods"`
	ConnectivityTests []ConnectivityTest  `json:"connectivityTests"`
	BlastRadius       []BlastRadius       `json:"blastRadius"`
	CNIInfo           CNIInfo             `json:"cniInfo"`
	NetworkMatrix     NetworkMatrix       `json:"networkMatrix"`
	Recommendations   []string            `json:"recommendations"`
	GeneratedAt       time.Time           `json:"generatedAt"`
}
