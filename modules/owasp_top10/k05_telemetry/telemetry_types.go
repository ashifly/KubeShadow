package k05_telemetry

import (
	"context"
	"time"

	"k8s.io/client-go/kubernetes"
)

// TelemetryFinding represents a telemetry/logging finding
type TelemetryFinding struct {
	ID          string    `json:"id"`
	Type        string    `json:"type"`
	Severity    string    `json:"severity"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Resource    string    `json:"resource"`
	Namespace   string    `json:"namespace"`
	RiskScore   float64   `json:"riskScore"`
	Remediation string    `json:"remediation"`
	Timestamp   time.Time `json:"timestamp"`
}

// TelemetrySummary represents summary statistics for telemetry findings
type TelemetrySummary struct {
	TotalFindings     int     `json:"totalFindings"`
	CriticalCount     int     `json:"criticalCount"`
	HighCount         int     `json:"highCount"`
	MediumCount       int     `json:"mediumCount"`
	LowCount          int     `json:"lowCount"`
	CoverageScore     float64 `json:"coverageScore"`
	RetentionScore    float64 `json:"retentionScore"`
	SIEMIntegration   bool    `json:"siemIntegration"`
	AuditEnabled      bool    `json:"auditEnabled"`
	EBPFEnabled       bool    `json:"ebpfEnabled"`
	NamespacesCovered int     `json:"namespacesCovered"`
	EventsLogged      int     `json:"eventsLogged"`
}

// TelemetryScanner represents the telemetry scanner
type TelemetryScanner struct {
	client    kubernetes.Interface
	namespace string
	ctx       context.Context
}

// AuditPolicy represents Kubernetes audit policy configuration
type AuditPolicy struct {
	Enabled     bool              `json:"enabled"`
	Level       string            `json:"level"`
	Rules       []AuditRule       `json:"rules"`
	Retention   int               `json:"retention"`
	Destination string            `json:"destination"`
	Metadata    map[string]string `json:"metadata"`
}

// AuditRule represents an audit rule
type AuditRule struct {
	Level      string   `json:"level"`
	Namespaces []string `json:"namespaces"`
	Users      []string `json:"users"`
	Verbs      []string `json:"verbs"`
	Resources  []string `json:"resources"`
}

// EBProbe represents eBPF probe configuration
type EBProbe struct {
	Name        string            `json:"name"`
	Type        string            `json:"type"`
	Enabled     bool              `json:"enabled"`
	Namespace   string            `json:"namespace"`
	Config      map[string]string `json:"config"`
	LastSeen    time.Time         `json:"lastSeen"`
	EventsCount int               `json:"eventsCount"`
}

// SIEMIntegration represents SIEM integration status
type SIEMIntegration struct {
	Provider    string            `json:"provider"`
	Enabled     bool              `json:"enabled"`
	Endpoint    string            `json:"endpoint"`
	Credentials map[string]string `json:"credentials"`
	LastSync    time.Time         `json:"lastSync"`
	EventsSent  int               `json:"eventsSent"`
	ErrorRate   float64           `json:"errorRate"`
}

// LogSink represents log forwarding configuration
type LogSink struct {
	Name        string            `json:"name"`
	Type        string            `json:"type"`
	Destination string            `json:"destination"`
	Enabled     bool              `json:"enabled"`
	Filters     map[string]string `json:"filters"`
	Retention   int               `json:"retention"`
	LastUpdate  time.Time         `json:"lastUpdate"`
}

// TelemetryReport represents the complete telemetry report
type TelemetryReport struct {
	Findings        []TelemetryFinding     `json:"findings"`
	Summary         TelemetrySummary       `json:"summary"`
	AuditPolicy     AuditPolicy            `json:"auditPolicy"`
	EBProbes        []EBProbe              `json:"ebProbes"`
	SIEMIntegration SIEMIntegration        `json:"siemIntegration"`
	LogSinks        []LogSink              `json:"logSinks"`
	Recommendations []string               `json:"recommendations"`
	DetectionTest   *DetectionPipelineTest `json:"detectionTest,omitempty"`
	GeneratedAt     time.Time              `json:"generatedAt"`
}
