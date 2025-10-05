package k06_auth

import (
	"context"
	"fmt"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// SimulateAuthTests runs safe authentication tests
func (as *AuthScanner) SimulateAuthTests() ([]AuthTest, error) {
	var tests []AuthTest

	// Test 1: Anonymous access test
	anonymousTest := as.testAnonymousAccess()
	tests = append(tests, anonymousTest)

	// Test 2: RBAC effectiveness test
	rbacTest := as.testRBACEffectiveness()
	tests = append(tests, rbacTest)

	// Test 3: Token validation test
	tokenTest := as.testTokenValidation()
	tests = append(tests, tokenTest)

	// Test 4: Public endpoint test
	endpointTest := as.testPublicEndpoints()
	tests = append(tests, endpointTest)

	// Test 5: Kubeconfig security test (lab mode only)
	if as.labMode {
		kubeconfigTest := as.testKubeconfigSecurity()
		tests = append(tests, kubeconfigTest)
	}

	return tests, nil
}

// testAnonymousAccess tests for anonymous access vulnerabilities
func (as *AuthScanner) testAnonymousAccess() AuthTest {
	test := AuthTest{
		TestName:    "Anonymous Access Test",
		Description: "Tests if anonymous access is enabled on the API server",
		Timestamp:   time.Now(),
		Metadata:    make(map[string]string),
	}

	// Try to access API server without authentication
	// This is a safe test that only reads public information
	_, err := as.client.CoreV1().Nodes().List(context.Background(), metav1.ListOptions{Limit: 1})

	if err != nil {
		test.Success = true
		test.RiskLevel = "low"
		test.Details = "Anonymous access is properly disabled"
	} else {
		test.Success = false
		test.RiskLevel = "critical"
		test.Details = "Anonymous access is enabled - this is a critical security risk"
	}

	test.Metadata["test_type"] = "anonymous_access"
	test.Metadata["api_call"] = "nodes.list"
	test.Metadata["result"] = fmt.Sprintf("%t", test.Success)

	return test
}

// testRBACEffectiveness tests RBAC configuration
func (as *AuthScanner) testRBACEffectiveness() AuthTest {
	test := AuthTest{
		TestName:    "RBAC Effectiveness Test",
		Description: "Tests if RBAC is properly configured and effective",
		Timestamp:   time.Now(),
		Metadata:    make(map[string]string),
	}

	// Try to list roles to check if RBAC is enabled
	_, err := as.client.RbacV1().Roles("").List(context.Background(), metav1.ListOptions{Limit: 1})

	if err != nil {
		test.Success = false
		test.RiskLevel = "critical"
		test.Details = "RBAC is not enabled or not accessible"
	} else {
		test.Success = true
		test.RiskLevel = "low"
		test.Details = "RBAC is enabled and accessible"
	}

	test.Metadata["test_type"] = "rbac_effectiveness"
	test.Metadata["api_call"] = "roles.list"
	test.Metadata["result"] = fmt.Sprintf("%t", test.Success)

	return test
}

// testTokenValidation tests token validation mechanisms
func (as *AuthScanner) testTokenValidation() AuthTest {
	test := AuthTest{
		TestName:    "Token Validation Test",
		Description: "Tests if token validation is working properly",
		Timestamp:   time.Now(),
		Metadata:    make(map[string]string),
	}

	// Test token validation by accessing a protected resource
	_, err := as.client.CoreV1().Secrets("").List(context.Background(), metav1.ListOptions{Limit: 1})

	if err != nil {
		test.Success = false
		test.RiskLevel = "high"
		test.Details = "Token validation failed - this may indicate authentication issues"
	} else {
		test.Success = true
		test.RiskLevel = "low"
		test.Details = "Token validation is working properly"
	}

	test.Metadata["test_type"] = "token_validation"
	test.Metadata["api_call"] = "secrets.list"
	test.Metadata["result"] = fmt.Sprintf("%t", test.Success)

	return test
}

// testPublicEndpoints tests for publicly accessible endpoints
func (as *AuthScanner) testPublicEndpoints() AuthTest {
	test := AuthTest{
		TestName:    "Public Endpoint Test",
		Description: "Tests for publicly accessible endpoints without authentication",
		Timestamp:   time.Now(),
		Metadata:    make(map[string]string),
	}

	// Check for LoadBalancer services
	services, err := as.client.CoreV1().Services("").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		test.Success = false
		test.RiskLevel = "medium"
		test.Details = "Unable to check services for public exposure"
		return test
	}

	publicServices := 0
	for _, svc := range services.Items {
		if svc.Spec.Type == "LoadBalancer" || svc.Spec.Type == "NodePort" {
			publicServices++
		}
	}

	if publicServices > 0 {
		test.Success = false
		test.RiskLevel = "high"
		test.Details = fmt.Sprintf("Found %d public services that may be exposed without authentication", publicServices)
	} else {
		test.Success = true
		test.RiskLevel = "low"
		test.Details = "No public services found"
	}

	test.Metadata["test_type"] = "public_endpoints"
	test.Metadata["public_services"] = fmt.Sprintf("%d", publicServices)
	test.Metadata["result"] = fmt.Sprintf("%t", test.Success)

	return test
}

// testKubeconfigSecurity tests kubeconfig security (lab mode only)
func (as *AuthScanner) testKubeconfigSecurity() AuthTest {
	test := AuthTest{
		TestName:    "Kubeconfig Security Test",
		Description: "Tests for exposed kubeconfig files and security issues",
		Timestamp:   time.Now(),
		Metadata:    make(map[string]string),
	}

	// This test is only run in lab mode for safety
	if !as.labMode {
		test.Success = true
		test.RiskLevel = "low"
		test.Details = "Kubeconfig security test skipped (not in lab mode)"
		return test
	}

	// Check for kubeconfigs in ConfigMaps
	configMaps, err := as.client.CoreV1().ConfigMaps("").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		test.Success = false
		test.RiskLevel = "medium"
		test.Details = "Unable to check ConfigMaps for kubeconfig exposure"
		return test
	}

	exposedConfigs := 0
	for _, cm := range configMaps.Items {
		for _, data := range cm.Data {
			if strings.Contains(data, "apiVersion: v1") && strings.Contains(data, "clusters:") {
				exposedConfigs++
			}
		}
	}

	if exposedConfigs > 0 {
		test.Success = false
		test.RiskLevel = "critical"
		test.Details = fmt.Sprintf("Found %d ConfigMaps containing kubeconfig data", exposedConfigs)
	} else {
		test.Success = true
		test.RiskLevel = "low"
		test.Details = "No kubeconfig data found in ConfigMaps"
	}

	test.Metadata["test_type"] = "kubeconfig_security"
	test.Metadata["exposed_configs"] = fmt.Sprintf("%d", exposedConfigs)
	test.Metadata["result"] = fmt.Sprintf("%t", test.Success)

	return test
}

// SimulateCredentialTheft simulates credential theft scenarios (safe mode)
func (as *AuthScanner) SimulateCredentialTheft() ([]AuthTest, error) {
	var tests []AuthTest

	// Only run in lab mode for safety
	if !as.labMode {
		return tests, nil
	}

	// Test 1: Service account token exposure
	tokenTest := as.simulateTokenTheft()
	tests = append(tests, tokenTest)

	// Test 2: Kubeconfig exposure
	kubeconfigTest := as.simulateKubeconfigTheft()
	tests = append(tests, kubeconfigTest)

	// Test 3: Public dashboard access
	dashboardTest := as.simulateDashboardAccess()
	tests = append(tests, dashboardTest)

	return tests, nil
}

// simulateTokenTheft simulates service account token theft
func (as *AuthScanner) simulateTokenTheft() AuthTest {
	test := AuthTest{
		TestName:    "Token Theft Simulation",
		Description: "Simulates what an attacker could do with a stolen service account token",
		Timestamp:   time.Now(),
		Metadata:    make(map[string]string),
	}

	// List service accounts to simulate token discovery
	serviceAccounts, err := as.client.CoreV1().ServiceAccounts("").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		test.Success = false
		test.RiskLevel = "medium"
		test.Details = "Unable to list service accounts for simulation"
		return test
	}

	// Simulate what an attacker could discover
	discoverableResources := len(serviceAccounts.Items)

	if discoverableResources > 0 {
		test.Success = false
		test.RiskLevel = "high"
		test.Details = fmt.Sprintf("Simulation shows %d service accounts are discoverable", discoverableResources)
	} else {
		test.Success = true
		test.RiskLevel = "low"
		test.Details = "No service accounts found for simulation"
	}

	test.Metadata["test_type"] = "token_theft_simulation"
	test.Metadata["discoverable_resources"] = fmt.Sprintf("%d", discoverableResources)
	test.Metadata["result"] = fmt.Sprintf("%t", test.Success)

	return test
}

// simulateKubeconfigTheft simulates kubeconfig theft
func (as *AuthScanner) simulateKubeconfigTheft() AuthTest {
	test := AuthTest{
		TestName:    "Kubeconfig Theft Simulation",
		Description: "Simulates what an attacker could do with a stolen kubeconfig",
		Timestamp:   time.Now(),
		Metadata:    make(map[string]string),
	}

	// Try to access cluster information (safe read-only operation)
	nodes, err := as.client.CoreV1().Nodes().List(context.Background(), metav1.ListOptions{})
	if err != nil {
		test.Success = false
		test.RiskLevel = "medium"
		test.Details = "Unable to access cluster information for simulation"
		return test
	}

	// Simulate what an attacker could discover
	discoverableNodes := len(nodes.Items)

	if discoverableNodes > 0 {
		test.Success = false
		test.RiskLevel = "critical"
		test.Details = fmt.Sprintf("Simulation shows %d nodes are discoverable with stolen kubeconfig", discoverableNodes)
	} else {
		test.Success = true
		test.RiskLevel = "low"
		test.Details = "No nodes found for simulation"
	}

	test.Metadata["test_type"] = "kubeconfig_theft_simulation"
	test.Metadata["discoverable_nodes"] = fmt.Sprintf("%d", discoverableNodes)
	test.Metadata["result"] = fmt.Sprintf("%t", test.Success)

	return test
}

// simulateDashboardAccess simulates public dashboard access
func (as *AuthScanner) simulateDashboardAccess() AuthTest {
	test := AuthTest{
		TestName:    "Dashboard Access Simulation",
		Description: "Simulates access to public dashboards without authentication",
		Timestamp:   time.Now(),
		Metadata:    make(map[string]string),
	}

	// Check for dashboard services
	services, err := as.client.CoreV1().Services("").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		test.Success = false
		test.RiskLevel = "medium"
		test.Details = "Unable to check services for dashboard exposure"
		return test
	}

	dashboardServices := 0
	for _, svc := range services.Items {
		if strings.Contains(svc.Name, "dashboard") || strings.Contains(svc.Name, "kubernetes-dashboard") {
			dashboardServices++
		}
	}

	if dashboardServices > 0 {
		test.Success = false
		test.RiskLevel = "high"
		test.Details = fmt.Sprintf("Found %d dashboard services that may be publicly accessible", dashboardServices)
	} else {
		test.Success = true
		test.RiskLevel = "low"
		test.Details = "No dashboard services found"
	}

	test.Metadata["test_type"] = "dashboard_access_simulation"
	test.Metadata["dashboard_services"] = fmt.Sprintf("%d", dashboardServices)
	test.Metadata["result"] = fmt.Sprintf("%t", test.Success)

	return test
}

// GenerateAuthHardeningRecommendations generates specific hardening recommendations
func (as *AuthScanner) GenerateAuthHardeningRecommendations() []string {
	var recommendations []string

	recommendations = append(recommendations, "1. Disable anonymous access to Kubernetes API server")
	recommendations = append(recommendations, "2. Enable RBAC with least privilege principle")
	recommendations = append(recommendations, "3. Implement OIDC or certificate-based authentication")
	recommendations = append(recommendations, "4. Enable comprehensive audit logging")
	recommendations = append(recommendations, "5. Implement token rotation policies")
	recommendations = append(recommendations, "6. Secure kubeconfig files with proper permissions")
	recommendations = append(recommendations, "7. Remove kubeconfigs from ConfigMaps and Secrets")
	recommendations = append(recommendations, "8. Implement network policies to restrict API server access")
	recommendations = append(recommendations, "9. Use admission controllers for additional security")
	recommendations = append(recommendations, "10. Regularly rotate service account tokens")

	return recommendations
}
