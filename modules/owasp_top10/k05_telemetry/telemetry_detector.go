package k05_telemetry

import (
	"context"
	"fmt"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// NewTelemetryScanner creates a new telemetry scanner
func NewTelemetryScanner(kubeconfig string, namespace string) (*TelemetryScanner, error) {
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

	return &TelemetryScanner{
		client:    clientset,
		namespace: namespace,
		ctx:       context.Background(),
	}, nil
}

// DetectAuditLogging detects Kubernetes audit logging configuration
func (ts *TelemetryScanner) DetectAuditLogging() (AuditPolicy, []TelemetryFinding, error) {
	var findings []TelemetryFinding
	auditPolicy := AuditPolicy{
		Enabled: false,
		Level:   "None",
	}

	// Check for audit policy ConfigMap
	configMaps, err := ts.client.CoreV1().ConfigMaps("").List(ts.ctx, metav1.ListOptions{
		LabelSelector: "audit-policy=true",
	})
	if err == nil && len(configMaps.Items) > 0 {
		auditPolicy.Enabled = true
		auditPolicy.Level = "Metadata"
	} else {
		findings = append(findings, TelemetryFinding{
			ID:          "audit-001",
			Type:        "audit",
			Severity:    "high",
			Title:       "Kubernetes Audit Logging Disabled",
			Description: "No audit policy ConfigMap found. Audit logging is not configured.",
			Resource:    "cluster",
			Namespace:   "all",
			RiskScore:   8.5,
			Remediation: "Enable Kubernetes audit logging by creating an audit policy ConfigMap and configuring the API server.",
			Timestamp:   time.Now(),
		})
	}

	// Check for audit webhook configuration
	webhooks, err := ts.client.AdmissionregistrationV1().ValidatingWebhookConfigurations().List(ts.ctx, metav1.ListOptions{})
	if err == nil {
		auditWebhookFound := false
		for _, webhook := range webhooks.Items {
			if strings.Contains(webhook.Name, "audit") {
				auditWebhookFound = true
				break
			}
		}
		if !auditWebhookFound {
			findings = append(findings, TelemetryFinding{
				ID:          "audit-002",
				Type:        "audit",
				Severity:    "medium",
				Title:       "No Audit Webhook Configuration",
				Description: "No audit webhook configuration found for centralized audit logging.",
				Resource:    "cluster",
				Namespace:   "all",
				RiskScore:   6.0,
				Remediation: "Configure audit webhook to forward audit logs to external systems.",
				Timestamp:   time.Now(),
			})
		}
	}

	return auditPolicy, findings, nil
}

// DetectEBProbes detects eBPF-based security monitoring tools
func (ts *TelemetryScanner) DetectEBProbes() ([]EBProbe, []TelemetryFinding, error) {
	var findings []TelemetryFinding
	var probes []EBProbe

	// Check for Falco
	falcoPods, err := ts.client.CoreV1().Pods("").List(ts.ctx, metav1.ListOptions{
		LabelSelector: "app=falco",
	})
	if err == nil && len(falcoPods.Items) > 0 {
		probes = append(probes, EBProbe{
			Name:      "falco",
			Type:      "security",
			Enabled:   true,
			Namespace: falcoPods.Items[0].Namespace,
			Config: map[string]string{
				"driver": "ebpf",
				"rules":  "enabled",
			},
			LastSeen:    time.Now(),
			EventsCount: 0, // Would need to query metrics
		})
	} else {
		findings = append(findings, TelemetryFinding{
			ID:          "ebpf-001",
			Type:        "ebpf",
			Severity:    "high",
			Title:       "Falco eBPF Security Monitoring Not Detected",
			Description: "Falco runtime security monitoring is not deployed.",
			Resource:    "cluster",
			Namespace:   "all",
			RiskScore:   8.0,
			Remediation: "Deploy Falco with eBPF driver for runtime security monitoring.",
			Timestamp:   time.Now(),
		})
	}

	// Check for Tetragon
	tetragonPods, err := ts.client.CoreV1().Pods("").List(ts.ctx, metav1.ListOptions{
		LabelSelector: "app=tetragon",
	})
	if err == nil && len(tetragonPods.Items) > 0 {
		probes = append(probes, EBProbe{
			Name:      "tetragon",
			Type:      "security",
			Enabled:   true,
			Namespace: tetragonPods.Items[0].Namespace,
			Config: map[string]string{
				"driver": "ebpf",
				"events": "enabled",
			},
			LastSeen:    time.Now(),
			EventsCount: 0,
		})
	} else {
		findings = append(findings, TelemetryFinding{
			ID:          "ebpf-002",
			Type:        "ebpf",
			Severity:    "medium",
			Title:       "Tetragon eBPF Monitoring Not Detected",
			Description: "Tetragon eBPF-based security monitoring is not deployed.",
			Resource:    "cluster",
			Namespace:   "all",
			RiskScore:   6.5,
			Remediation: "Deploy Tetragon for eBPF-based security monitoring and observability.",
			Timestamp:   time.Now(),
		})
	}

	// Check for other eBPF tools
	ebpfPods, err := ts.client.CoreV1().Pods("").List(ts.ctx, metav1.ListOptions{
		LabelSelector: "ebpf=true",
	})
	if err == nil && len(ebpfPods.Items) > 0 {
		for _, pod := range ebpfPods.Items {
			probes = append(probes, EBProbe{
				Name:      pod.Name,
				Type:      "custom",
				Enabled:   true,
				Namespace: pod.Namespace,
				Config:    pod.Annotations,
				LastSeen:  time.Now(),
			})
		}
	}

	return probes, findings, nil
}

// DetectSIEMIntegration detects SIEM integration and log forwarding
func (ts *TelemetryScanner) DetectSIEMIntegration() (SIEMIntegration, []LogSink, []TelemetryFinding, error) {
	var findings []TelemetryFinding
	var logSinks []LogSink
	siemIntegration := SIEMIntegration{
		Enabled: false,
	}

	// Check for log forwarding DaemonSets
	daemonSets, err := ts.client.AppsV1().DaemonSets("").List(ts.ctx, metav1.ListOptions{
		LabelSelector: "logging=true",
	})
	if err == nil && len(daemonSets.Items) > 0 {
		siemIntegration.Enabled = true
		siemIntegration.Provider = "kubernetes"
		siemIntegration.LastSync = time.Now()
	} else {
		findings = append(findings, TelemetryFinding{
			ID:          "siem-001",
			Type:        "siem",
			Severity:    "high",
			Title:       "No Log Forwarding Detected",
			Description: "No log forwarding DaemonSets found for SIEM integration.",
			Resource:    "cluster",
			Namespace:   "all",
			RiskScore:   8.5,
			Remediation: "Deploy log forwarding agents (Fluentd, Fluent Bit, or similar) to forward logs to SIEM.",
			Timestamp:   time.Now(),
		})
	}

	// Check for cloud provider log sinks
	configMaps, err := ts.client.CoreV1().ConfigMaps("").List(ts.ctx, metav1.ListOptions{
		LabelSelector: "log-sink=true",
	})
	if err == nil {
		for _, cm := range configMaps.Items {
			logSinks = append(logSinks, LogSink{
				Name:        cm.Name,
				Type:        cm.Labels["sink-type"],
				Destination: cm.Data["destination"],
				Enabled:     true,
				Filters:     cm.Data,
				LastUpdate:  time.Now(),
			})
		}
	}

	// Check for specific cloud provider integrations
	// AWS CloudWatch
	cloudwatchPods, err := ts.client.CoreV1().Pods("").List(ts.ctx, metav1.ListOptions{
		LabelSelector: "cloudwatch=true",
	})
	if err == nil && len(cloudwatchPods.Items) > 0 {
		siemIntegration.Provider = "aws-cloudwatch"
		siemIntegration.Enabled = true
	}

	// GCP Stackdriver
	stackdriverPods, err := ts.client.CoreV1().Pods("").List(ts.ctx, metav1.ListOptions{
		LabelSelector: "stackdriver=true",
	})
	if err == nil && len(stackdriverPods.Items) > 0 {
		siemIntegration.Provider = "gcp-stackdriver"
		siemIntegration.Enabled = true
	}

	// Azure Monitor
	azurePods, err := ts.client.CoreV1().Pods("").List(ts.ctx, metav1.ListOptions{
		LabelSelector: "azure-monitor=true",
	})
	if err == nil && len(azurePods.Items) > 0 {
		siemIntegration.Provider = "azure-monitor"
		siemIntegration.Enabled = true
	}

	if !siemIntegration.Enabled {
		findings = append(findings, TelemetryFinding{
			ID:          "siem-002",
			Type:        "siem",
			Severity:    "critical",
			Title:       "No SIEM Integration Detected",
			Description: "No SIEM integration found. Logs are not being forwarded to security monitoring systems.",
			Resource:    "cluster",
			Namespace:   "all",
			RiskScore:   9.5,
			Remediation: "Integrate with SIEM solution (Splunk, ELK, QRadar, etc.) for centralized security monitoring.",
			Timestamp:   time.Now(),
		})
	}

	return siemIntegration, logSinks, findings, nil
}

// DetectLogRetention detects log retention policies
func (ts *TelemetryScanner) DetectLogRetention() ([]TelemetryFinding, error) {
	var findings []TelemetryFinding

	// Check for log retention ConfigMaps
	configMaps, err := ts.client.CoreV1().ConfigMaps("").List(ts.ctx, metav1.ListOptions{
		LabelSelector: "log-retention=true",
	})
	if err == nil && len(configMaps.Items) == 0 {
		findings = append(findings, TelemetryFinding{
			ID:          "retention-001",
			Type:        "retention",
			Severity:    "medium",
			Title:       "No Log Retention Policy",
			Description: "No log retention policy found. Logs may accumulate indefinitely.",
			Resource:    "cluster",
			Namespace:   "all",
			RiskScore:   5.5,
			Remediation: "Configure log retention policies to manage storage costs and compliance requirements.",
			Timestamp:   time.Now(),
		})
	}

	// Check for log rotation
	pods, err := ts.client.CoreV1().Pods("").List(ts.ctx, metav1.ListOptions{
		LabelSelector: "log-rotation=true",
	})
	if err == nil && len(pods.Items) == 0 {
		findings = append(findings, TelemetryFinding{
			ID:          "retention-002",
			Type:        "retention",
			Severity:    "low",
			Title:       "No Log Rotation Configured",
			Description: "No log rotation configuration found. Log files may grow indefinitely.",
			Resource:    "cluster",
			Namespace:   "all",
			RiskScore:   4.0,
			Remediation: "Configure log rotation to prevent disk space issues.",
			Timestamp:   time.Now(),
		})
	}

	return findings, nil
}
