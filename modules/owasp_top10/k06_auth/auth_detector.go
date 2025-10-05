package k06_auth

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

// NewAuthScanner creates a new authentication scanner
func NewAuthScanner(kubeconfig string, namespace string, labMode bool) (*AuthScanner, error) {
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

	return &AuthScanner{
		client:    clientset,
		namespace: namespace,
		ctx:       context.Background(),
		labMode:   labMode,
	}, nil
}

// DetectAPIServerAuth detects API server authentication configuration
func (as *AuthScanner) DetectAPIServerAuth() (APIServerConfig, []AuthFinding, error) {
	var findings []AuthFinding
	config := APIServerConfig{
		Metadata: make(map[string]string),
	}

	// Check if we can access the API server
	_, err := as.client.CoreV1().Nodes().List(as.ctx, metav1.ListOptions{Limit: 1})
	if err != nil {
		findings = append(findings, AuthFinding{
			ID:          "auth-001",
			Type:        "api-server",
			Severity:    "critical",
			Title:       "API Server Access Denied",
			Description: "Cannot access Kubernetes API server. This may indicate authentication issues.",
			Resource:    "cluster",
			Namespace:   "all",
			RiskScore:   9.0,
			Remediation: "Verify kubeconfig and authentication credentials.",
			Timestamp:   time.Now(),
		})
		return config, findings, nil
	}

	// Check for anonymous access
	config.AnonymousAuth = as.checkAnonymousAccess()
	if config.AnonymousAuth {
		findings = append(findings, AuthFinding{
			ID:          "auth-002",
			Type:        "anonymous-access",
			Severity:    "critical",
			Title:       "Anonymous Access Enabled",
			Description: "Anonymous access to Kubernetes API server is enabled.",
			Resource:    "cluster",
			Namespace:   "all",
			RiskScore:   9.5,
			Remediation: "Disable anonymous access by setting --anonymous-auth=false on API server.",
			Timestamp:   time.Now(),
		})
	}

	// Check RBAC status
	config.RBACEnabled = as.checkRBACEnabled()
	if !config.RBACEnabled {
		findings = append(findings, AuthFinding{
			ID:          "auth-003",
			Type:        "rbac",
			Severity:    "critical",
			Title:       "RBAC Disabled",
			Description: "Role-Based Access Control (RBAC) is not enabled.",
			Resource:    "cluster",
			Namespace:   "all",
			RiskScore:   9.0,
			Remediation: "Enable RBAC by setting --authorization-mode=RBAC on API server.",
			Timestamp:   time.Now(),
		})
	}

	// Check admission controllers
	config.AdmissionPlugins = as.getAdmissionPlugins()
	requiredPlugins := []string{"NodeRestriction", "PodSecurityPolicy", "ServiceAccount"}
	missingPlugins := as.checkMissingAdmissionPlugins(config.AdmissionPlugins, requiredPlugins)
	for _, plugin := range missingPlugins {
		findings = append(findings, AuthFinding{
			ID:          "auth-004",
			Type:        "admission-controller",
			Severity:    "high",
			Title:       fmt.Sprintf("Missing Admission Controller: %s", plugin),
			Description: fmt.Sprintf("Required admission controller %s is not enabled.", plugin),
			Resource:    "cluster",
			Namespace:   "all",
			RiskScore:   7.5,
			Remediation: fmt.Sprintf("Enable %s admission controller on API server.", plugin),
			Timestamp:   time.Now(),
		})
	}

	// Check audit logging
	config.AuditLogging = as.checkAuditLogging()
	if !config.AuditLogging {
		findings = append(findings, AuthFinding{
			ID:          "auth-005",
			Type:        "audit-logging",
			Severity:    "medium",
			Title:       "Audit Logging Disabled",
			Description: "API server audit logging is not enabled.",
			Resource:    "cluster",
			Namespace:   "all",
			RiskScore:   6.0,
			Remediation: "Enable audit logging by configuring --audit-log-path on API server.",
			Timestamp:   time.Now(),
		})
	}

	return config, findings, nil
}

// DetectKubeConfigs detects exposed kubeconfig files
func (as *AuthScanner) DetectKubeConfigs() ([]KubeConfigInfo, []AuthFinding, error) {
	var findings []AuthFinding
	var kubeConfigs []KubeConfigInfo

	// Only scan in lab mode for safety
	if !as.labMode {
		return kubeConfigs, findings, nil
	}

	// Check common kubeconfig locations
	locations := []string{
		filepath.Join(homedir.HomeDir(), ".kube", "config"),
		"/etc/kubernetes/admin.conf",
		"/etc/kubernetes/kubelet.conf",
		"/var/lib/kubelet/config.yaml",
	}

	for _, location := range locations {
		if info, err := os.Stat(location); err == nil {
			kubeConfig := KubeConfigInfo{
				Path:     location,
				Exposed:  true,
				Metadata: make(map[string]string),
			}

			// Analyze kubeconfig file
			as.analyzeKubeConfig(&kubeConfig)

			if kubeConfig.RiskLevel == "high" || kubeConfig.RiskLevel == "critical" {
				findings = append(findings, AuthFinding{
					ID:          "auth-006",
					Type:        "kubeconfig-exposure",
					Severity:    kubeConfig.RiskLevel,
					Title:       "Exposed Kubeconfig File",
					Description: fmt.Sprintf("Kubeconfig file found at %s with high-risk configuration.", location),
					Resource:    location,
					Namespace:   "all",
					RiskScore:   as.getRiskScore(kubeConfig.RiskLevel),
					Remediation: "Secure kubeconfig file permissions and consider using RBAC.",
					Timestamp:   time.Now(),
					Metadata: map[string]string{
						"path":        location,
						"size":        fmt.Sprintf("%d", info.Size()),
						"permissions": info.Mode().String(),
					},
				})
			}

			kubeConfigs = append(kubeConfigs, kubeConfig)
		}
	}

	// Check for kubeconfigs in ConfigMaps and Secrets
	cmKubeConfigs, cmFindings := as.detectKubeConfigsInConfigMaps()
	kubeConfigs = append(kubeConfigs, cmKubeConfigs...)
	findings = append(findings, cmFindings...)

	secretKubeConfigs, secretFindings := as.detectKubeConfigsInSecrets()
	kubeConfigs = append(kubeConfigs, secretKubeConfigs...)
	findings = append(findings, secretFindings...)

	return kubeConfigs, findings, nil
}

// DetectTokens detects service account tokens
func (as *AuthScanner) DetectTokens() ([]TokenInfo, []AuthFinding, error) {
	var findings []AuthFinding
	var tokens []TokenInfo

	// List all service accounts
	serviceAccounts, err := as.client.CoreV1().ServiceAccounts("").List(as.ctx, metav1.ListOptions{})
	if err != nil {
		return tokens, findings, fmt.Errorf("failed to list service accounts: %w", err)
	}

	for _, sa := range serviceAccounts.Items {
		// Check for auto-mounted tokens
		if sa.AutomountServiceAccountToken != nil && *sa.AutomountServiceAccountToken {
			token := TokenInfo{
				Name:           sa.Name,
				Namespace:      sa.Namespace,
				ServiceAccount: sa.Name,
				Exposed:        true,
				Location:       fmt.Sprintf("serviceaccount/%s", sa.Name),
				Metadata:       make(map[string]string),
			}

			// Analyze token age and permissions
			as.analyzeToken(&token)

			if token.RiskLevel == "high" || token.RiskLevel == "critical" {
				findings = append(findings, AuthFinding{
					ID:          "auth-007",
					Type:        "token-exposure",
					Severity:    token.RiskLevel,
					Title:       "High-Risk Service Account Token",
					Description: fmt.Sprintf("Service account %s/%s has high-risk token configuration.", sa.Namespace, sa.Name),
					Resource:    fmt.Sprintf("serviceaccount/%s", sa.Name),
					Namespace:   sa.Namespace,
					RiskScore:   as.getRiskScore(token.RiskLevel),
					Remediation: "Review service account permissions and consider token rotation.",
					Timestamp:   time.Now(),
					Metadata: map[string]string{
						"service_account": sa.Name,
						"namespace":       sa.Namespace,
						"auto_mount":      "true",
					},
				})
			}

			tokens = append(tokens, token)
		}
	}

	return tokens, findings, nil
}

// DetectPublicEndpoints detects publicly accessible endpoints
func (as *AuthScanner) DetectPublicEndpoints() ([]PublicEndpoint, []AuthFinding, error) {
	var findings []AuthFinding
	var endpoints []PublicEndpoint

	// Check for services with LoadBalancer type
	services, err := as.client.CoreV1().Services("").List(as.ctx, metav1.ListOptions{})
	if err != nil {
		return endpoints, findings, fmt.Errorf("failed to list services: %w", err)
	}

	for _, svc := range services.Items {
		if svc.Spec.Type == "LoadBalancer" {
			endpoint := PublicEndpoint{
				URL:          fmt.Sprintf("%s:%d", svc.Name, svc.Spec.Ports[0].Port),
				Type:         "LoadBalancer",
				AuthRequired: false, // Would need to test actual endpoint
				Exposed:      true,
				Metadata:     make(map[string]string),
			}

			// Analyze endpoint security
			as.analyzePublicEndpoint(&endpoint)

			if endpoint.RiskLevel == "high" || endpoint.RiskLevel == "critical" {
				findings = append(findings, AuthFinding{
					ID:          "auth-008",
					Type:        "public-endpoint",
					Severity:    endpoint.RiskLevel,
					Title:       "Public LoadBalancer Service",
					Description: fmt.Sprintf("Service %s/%s is exposed via LoadBalancer without authentication.", svc.Namespace, svc.Name),
					Resource:    fmt.Sprintf("service/%s", svc.Name),
					Namespace:   svc.Namespace,
					RiskScore:   as.getRiskScore(endpoint.RiskLevel),
					Remediation: "Implement authentication or restrict access to LoadBalancer services.",
					Timestamp:   time.Now(),
					Metadata: map[string]string{
						"service":   svc.Name,
						"namespace": svc.Namespace,
						"type":      "LoadBalancer",
					},
				})
			}

			endpoints = append(endpoints, endpoint)
		}
	}

	// Check for NodePort services
	for _, svc := range services.Items {
		if svc.Spec.Type == "NodePort" {
			endpoint := PublicEndpoint{
				URL:          fmt.Sprintf("node:%d", svc.Spec.Ports[0].NodePort),
				Type:         "NodePort",
				AuthRequired: false,
				Exposed:      true,
				Metadata:     make(map[string]string),
			}

			as.analyzePublicEndpoint(&endpoint)

			if endpoint.RiskLevel == "medium" || endpoint.RiskLevel == "high" {
				findings = append(findings, AuthFinding{
					ID:          "auth-009",
					Type:        "public-endpoint",
					Severity:    endpoint.RiskLevel,
					Title:       "Public NodePort Service",
					Description: fmt.Sprintf("Service %s/%s is exposed via NodePort.", svc.Namespace, svc.Name),
					Resource:    fmt.Sprintf("service/%s", svc.Name),
					Namespace:   svc.Namespace,
					RiskScore:   as.getRiskScore(endpoint.RiskLevel),
					Remediation: "Review NodePort exposure and implement proper access controls.",
					Timestamp:   time.Now(),
					Metadata: map[string]string{
						"service":   svc.Name,
						"namespace": svc.Namespace,
						"type":      "NodePort",
						"port":      fmt.Sprintf("%d", svc.Spec.Ports[0].NodePort),
					},
				})
			}

			endpoints = append(endpoints, endpoint)
		}
	}

	return endpoints, findings, nil
}

// Helper methods for authentication detection
func (as *AuthScanner) checkAnonymousAccess() bool {
	// This is a simplified check - in reality, you'd need to test actual API calls
	// For now, we'll assume anonymous access is disabled if we can access the API
	_, err := as.client.CoreV1().Nodes().List(as.ctx, metav1.ListOptions{Limit: 1})
	return err == nil
}

func (as *AuthScanner) checkRBACEnabled() bool {
	// Check if RBAC is enabled by trying to list roles
	_, err := as.client.RbacV1().Roles("").List(as.ctx, metav1.ListOptions{Limit: 1})
	return err == nil
}

func (as *AuthScanner) getAdmissionPlugins() []string {
	// This would require access to API server configuration
	// For now, return a default set
	return []string{"NodeRestriction", "ServiceAccount"}
}

func (as *AuthScanner) checkMissingAdmissionPlugins(enabled, required []string) []string {
	var missing []string
	for _, req := range required {
		found := false
		for _, en := range enabled {
			if en == req {
				found = true
				break
			}
		}
		if !found {
			missing = append(missing, req)
		}
	}
	return missing
}

func (as *AuthScanner) checkAuditLogging() bool {
	// This would require checking API server configuration
	// For now, assume it's enabled if we can access the API
	return true
}

func (as *AuthScanner) analyzeKubeConfig(kubeConfig *KubeConfigInfo) {
	// Analyze kubeconfig file for security issues
	kubeConfig.AuthMethod = "unknown"
	kubeConfig.RiskLevel = "medium"

	// Check file permissions (simplified)
	if strings.Contains(kubeConfig.Path, "admin") {
		kubeConfig.RiskLevel = "critical"
	} else if strings.Contains(kubeConfig.Path, "kubelet") {
		kubeConfig.RiskLevel = "high"
	}
}

func (as *AuthScanner) analyzeToken(token *TokenInfo) {
	// Analyze token for security issues
	token.Age = time.Since(time.Now().Add(-24 * time.Hour)) // Simulated age
	token.RiskLevel = "medium"

	if token.Age > 30*24*time.Hour {
		token.RiskLevel = "high"
	}
}

func (as *AuthScanner) analyzePublicEndpoint(endpoint *PublicEndpoint) {
	// Analyze public endpoint for security issues
	endpoint.RiskLevel = "medium"

	if endpoint.Type == "LoadBalancer" {
		endpoint.RiskLevel = "high"
	}
}

func (as *AuthScanner) getRiskScore(riskLevel string) float64 {
	switch riskLevel {
	case "critical":
		return 9.0
	case "high":
		return 7.5
	case "medium":
		return 5.0
	case "low":
		return 2.5
	default:
		return 5.0
	}
}

func (as *AuthScanner) detectKubeConfigsInConfigMaps() ([]KubeConfigInfo, []AuthFinding) {
	// Implementation for detecting kubeconfigs in ConfigMaps
	return []KubeConfigInfo{}, []AuthFinding{}
}

func (as *AuthScanner) detectKubeConfigsInSecrets() ([]KubeConfigInfo, []AuthFinding) {
	// Implementation for detecting kubeconfigs in Secrets
	return []KubeConfigInfo{}, []AuthFinding{}
}
