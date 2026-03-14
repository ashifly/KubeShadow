package recon

import (
	"context"
	"fmt"
	"strings"

	"kubeshadow/pkg/logger"

	v1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// ComprehensiveScanResult represents the result of a comprehensive security scan
type ComprehensiveScanResult struct {
	PodVulnerabilities     []*VulnerabilityInfo
	ServiceVulnerabilities []*ServiceVulnerabilityInfo
	SecretVulnerabilities  []*SecretVulnerabilityInfo
	RBACVulnerabilities    []*RBACVulnerabilityInfo
	TotalVulnerabilities   int
}

// ServiceVulnerabilityInfo represents service-related vulnerabilities
type ServiceVulnerabilityInfo struct {
	ServiceName       string
	Namespace         string
	Severity          string
	VulnerabilityType string
	Description       string
	Recommendation    string
}

// SecretVulnerabilityInfo represents secret-related vulnerabilities
type SecretVulnerabilityInfo struct {
	SecretName        string
	Namespace         string
	Severity          string
	VulnerabilityType string
	Description       string
	Recommendation    string
}

// RBACVulnerabilityInfo represents RBAC-related vulnerabilities
type RBACVulnerabilityInfo struct {
	ResourceName      string
	Namespace         string
	Severity          string
	VulnerabilityType string
	Description       string
	Recommendation    string
}

// ComprehensiveSecurityScan performs a comprehensive security scan of the cluster
func ComprehensiveSecurityScan(ctx context.Context, kubeconfig string) (*ComprehensiveScanResult, error) {
	// Create Kubernetes client
	config, err := getKubeConfig(kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("failed to get kubeconfig: %v", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create clientset: %v", err)
	}

	result := &ComprehensiveScanResult{}

	// Scan pods for vulnerabilities
	logger.Info("🔍 Scanning pods for vulnerabilities...")
	podVulns, err := PodVulnerabilityScan(ctx, kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("failed to scan pods: %v", err)
	}
	result.PodVulnerabilities = podVulns

	// Scan services for vulnerabilities
	logger.Info("🔍 Scanning services for vulnerabilities...")
	serviceVulns, err := scanServicesForVulnerabilities(ctx, clientset)
	if err != nil {
		return nil, fmt.Errorf("failed to scan services: %v", err)
	}
	result.ServiceVulnerabilities = serviceVulns

	// Scan secrets for vulnerabilities
	logger.Info("🔍 Scanning secrets for vulnerabilities...")
	secretVulns, err := scanSecretsForVulnerabilities(ctx, clientset)
	if err != nil {
		return nil, fmt.Errorf("failed to scan secrets: %v", err)
	}
	result.SecretVulnerabilities = secretVulns

	// Scan RBAC for vulnerabilities
	logger.Info("🔍 Scanning RBAC for vulnerabilities...")
	rbacVulns, err := scanRBACForVulnerabilities(ctx, clientset)
	if err != nil {
		return nil, fmt.Errorf("failed to scan RBAC: %v", err)
	}
	result.RBACVulnerabilities = rbacVulns

	// Calculate total vulnerabilities
	result.TotalVulnerabilities = len(result.PodVulnerabilities) +
		len(result.ServiceVulnerabilities) +
		len(result.SecretVulnerabilities) +
		len(result.RBACVulnerabilities)

	return result, nil
}

// scanServicesForVulnerabilities scans services for security vulnerabilities
func scanServicesForVulnerabilities(ctx context.Context, clientset *kubernetes.Clientset) ([]*ServiceVulnerabilityInfo, error) {
	var vulnerabilities []*ServiceVulnerabilityInfo

	// Get all services
	services, err := clientset.CoreV1().Services("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list services: %v", err)
	}

	for _, service := range services.Items {
		// Check for NodePort services (external exposure)
		if service.Spec.Type == v1.ServiceTypeNodePort {
			vulnerabilities = append(vulnerabilities, &ServiceVulnerabilityInfo{
				ServiceName:       service.Name,
				Namespace:         service.Namespace,
				Severity:          "HIGH",
				VulnerabilityType: "nodePortExposure",
				Description:       fmt.Sprintf("Service '%s' is exposed via NodePort", service.Name),
				Recommendation:    "Use ClusterIP or LoadBalancer instead of NodePort for better security",
			})
		}

		// Check for LoadBalancer services (public exposure)
		if service.Spec.Type == v1.ServiceTypeLoadBalancer {
			vulnerabilities = append(vulnerabilities, &ServiceVulnerabilityInfo{
				ServiceName:       service.Name,
				Namespace:         service.Namespace,
				Severity:          "CRITICAL",
				VulnerabilityType: "loadBalancerExposure",
				Description:       fmt.Sprintf("Service '%s' is exposed via LoadBalancer (public access)", service.Name),
				Recommendation:    "Review LoadBalancer necessity and implement proper network policies",
			})
		}

		// Check for services without selectors (headless services)
		if len(service.Spec.Selector) == 0 {
			vulnerabilities = append(vulnerabilities, &ServiceVulnerabilityInfo{
				ServiceName:       service.Name,
				Namespace:         service.Namespace,
				Severity:          "MEDIUM",
				VulnerabilityType: "headlessService",
				Description:       fmt.Sprintf("Service '%s' has no selector (headless service)", service.Name),
				Recommendation:    "Review headless service necessity and security implications",
			})
		}
	}

	return vulnerabilities, nil
}

// scanSecretsForVulnerabilities scans secrets for security vulnerabilities
func scanSecretsForVulnerabilities(ctx context.Context, clientset *kubernetes.Clientset) ([]*SecretVulnerabilityInfo, error) {
	var vulnerabilities []*SecretVulnerabilityInfo

	// Get all secrets
	secrets, err := clientset.CoreV1().Secrets("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list secrets: %v", err)
	}

	for _, secret := range secrets.Items {
		// Check for secrets with weak encryption
		if secret.Type == v1.SecretTypeOpaque {
			// Check for base64 encoded secrets (basic check)
			for key, value := range secret.Data {
				if len(value) < 32 { // Short secrets might be weak
					vulnerabilities = append(vulnerabilities, &SecretVulnerabilityInfo{
						SecretName:        secret.Name,
						Namespace:         secret.Namespace,
						Severity:          "MEDIUM",
						VulnerabilityType: "weakSecret",
						Description:       fmt.Sprintf("Secret '%s' has short value for key '%s'", secret.Name, key),
						Recommendation:    "Use longer, more secure secrets",
					})
				}
			}
		}

		// Check for secrets with sensitive names
		sensitiveNames := []string{"password", "secret", "key", "token", "credential", "auth"}
		secretNameLower := strings.ToLower(secret.Name)
		for _, sensitive := range sensitiveNames {
			if strings.Contains(secretNameLower, sensitive) {
				vulnerabilities = append(vulnerabilities, &SecretVulnerabilityInfo{
					SecretName:        secret.Name,
					Namespace:         secret.Namespace,
					Severity:          "LOW",
					VulnerabilityType: "sensitiveSecretName",
					Description:       fmt.Sprintf("Secret '%s' has sensitive name pattern", secret.Name),
					Recommendation:    "Use less descriptive secret names to avoid information disclosure",
				})
				break
			}
		}
	}

	return vulnerabilities, nil
}

// scanRBACForVulnerabilities scans RBAC for security vulnerabilities
func scanRBACForVulnerabilities(ctx context.Context, clientset *kubernetes.Clientset) ([]*RBACVulnerabilityInfo, error) {
	var vulnerabilities []*RBACVulnerabilityInfo

	// Scan ClusterRoles for overly permissive permissions
	clusterRoles, err := clientset.RbacV1().ClusterRoles().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list cluster roles: %v", err)
	}

	for _, role := range clusterRoles.Items {
		// Check for overly permissive cluster roles
		if isOverlyPermissiveRole(&role) {
			vulnerabilities = append(vulnerabilities, &RBACVulnerabilityInfo{
				ResourceName:      role.Name,
				Namespace:         "cluster-wide",
				Severity:          "CRITICAL",
				VulnerabilityType: "overlyPermissiveClusterRole",
				Description:       fmt.Sprintf("ClusterRole '%s' has overly permissive permissions", role.Name),
				Recommendation:    "Apply principle of least privilege and restrict permissions",
			})
		}
	}

	// Scan ClusterRoleBindings for dangerous bindings
	clusterRoleBindings, err := clientset.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list cluster role bindings: %v", err)
	}

	for _, binding := range clusterRoleBindings.Items {
		// Check for cluster-admin bindings
		if binding.RoleRef.Name == "cluster-admin" {
			vulnerabilities = append(vulnerabilities, &RBACVulnerabilityInfo{
				ResourceName:      binding.Name,
				Namespace:         "cluster-wide",
				Severity:          "CRITICAL",
				VulnerabilityType: "clusterAdminBinding",
				Description:       fmt.Sprintf("ClusterRoleBinding '%s' grants cluster-admin privileges", binding.Name),
				Recommendation:    "Review cluster-admin bindings and use more restrictive roles",
			})
		}
	}

	// Scan Roles for overly permissive permissions
	roles, err := clientset.RbacV1().Roles("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list roles: %v", err)
	}

	for _, role := range roles.Items {
		// Check for overly permissive roles
		if isOverlyPermissiveRole(&role) {
			vulnerabilities = append(vulnerabilities, &RBACVulnerabilityInfo{
				ResourceName:      role.Name,
				Namespace:         role.Namespace,
				Severity:          "HIGH",
				VulnerabilityType: "overlyPermissiveRole",
				Description:       fmt.Sprintf("Role '%s' in namespace '%s' has overly permissive permissions", role.Name, role.Namespace),
				Recommendation:    "Apply principle of least privilege and restrict permissions",
			})
		}
	}

	return vulnerabilities, nil
}

// isOverlyPermissiveRole checks if a role has overly permissive permissions
func isOverlyPermissiveRole(role interface{}) bool {
	// This is a simplified check - in practice, you'd want more sophisticated analysis
	switch r := role.(type) {
	case *rbacv1.Role:
		for _, rule := range r.Rules {
			if len(rule.Resources) == 1 && rule.Resources[0] == "*" &&
				len(rule.Verbs) == 1 && rule.Verbs[0] == "*" {
				return true
			}
		}
	case *rbacv1.ClusterRole:
		for _, rule := range r.Rules {
			if len(rule.Resources) == 1 && rule.Resources[0] == "*" &&
				len(rule.Verbs) == 1 && rule.Verbs[0] == "*" {
				return true
			}
		}
	}
	return false
}

// PrintComprehensiveScanResults prints comprehensive scan results
func PrintComprehensiveScanResults(result *ComprehensiveScanResult) {
	logger.Info("🔍 COMPREHENSIVE SECURITY SCAN RESULTS")
	logger.Info("=====================================")
	logger.Info("")

	// Print pod vulnerabilities
	if len(result.PodVulnerabilities) > 0 {
		logger.Info("🐳 POD VULNERABILITIES (%d):", len(result.PodVulnerabilities))
		PrintVulnerabilities(result.PodVulnerabilities)
		logger.Info("")
	}

	// Print service vulnerabilities
	if len(result.ServiceVulnerabilities) > 0 {
		logger.Info("🌐 SERVICE VULNERABILITIES (%d):", len(result.ServiceVulnerabilities))
		for _, vuln := range result.ServiceVulnerabilities {
			logger.Info("  • %s/%s - %s: %s", vuln.Namespace, vuln.ServiceName, vuln.VulnerabilityType, vuln.Description)
			logger.Info("    Recommendation: %s", vuln.Recommendation)
			logger.Info("")
		}
	}

	// Print secret vulnerabilities
	if len(result.SecretVulnerabilities) > 0 {
		logger.Info("🔐 SECRET VULNERABILITIES (%d):", len(result.SecretVulnerabilities))
		for _, vuln := range result.SecretVulnerabilities {
			logger.Info("  • %s/%s - %s: %s", vuln.Namespace, vuln.SecretName, vuln.VulnerabilityType, vuln.Description)
			logger.Info("    Recommendation: %s", vuln.Recommendation)
			logger.Info("")
		}
	}

	// Print RBAC vulnerabilities
	if len(result.RBACVulnerabilities) > 0 {
		logger.Info("🔑 RBAC VULNERABILITIES (%d):", len(result.RBACVulnerabilities))
		for _, vuln := range result.RBACVulnerabilities {
			logger.Info("  • %s/%s - %s: %s", vuln.Namespace, vuln.ResourceName, vuln.VulnerabilityType, vuln.Description)
			logger.Info("    Recommendation: %s", vuln.Recommendation)
			logger.Info("")
		}
	}

	// Print summary
	logger.Info("📊 COMPREHENSIVE SCAN SUMMARY:")
	logger.Info("  🐳 Pod Vulnerabilities: %d", len(result.PodVulnerabilities))
	logger.Info("  🌐 Service Vulnerabilities: %d", len(result.ServiceVulnerabilities))
	logger.Info("  🔐 Secret Vulnerabilities: %d", len(result.SecretVulnerabilities))
	logger.Info("  🔑 RBAC Vulnerabilities: %d", len(result.RBACVulnerabilities))
	logger.Info("  📈 Total Vulnerabilities: %d", result.TotalVulnerabilities)
	logger.Info("")

	if result.TotalVulnerabilities == 0 {
		logger.Info("✅ No security vulnerabilities found in the cluster!")
	} else {
		logger.Info("🚨 Found %d total security vulnerabilities across all resources", result.TotalVulnerabilities)
	}
}
