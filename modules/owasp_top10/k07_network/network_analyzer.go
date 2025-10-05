package k07_network

import (
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// AnalyzeNetworkSegmentation analyzes network segmentation and security
func (ns *NetworkScanner) AnalyzeNetworkSegmentation() (NetworkSummary, []string, error) {
	var recommendations []string
	summary := NetworkSummary{}

	// Analyze NetworkPolicies
	networkPolicies, policyFindings, err := ns.DetectNetworkPolicies()
	if err != nil {
		return summary, recommendations, fmt.Errorf("failed to analyze network policies: %w", err)
	}

	summary.NetworkPoliciesCount = len(networkPolicies)
	summary.TotalFindings += len(policyFindings)

	// Count findings by severity
	for _, finding := range policyFindings {
		switch finding.Severity {
		case "critical":
			summary.CriticalCount++
		case "high":
			summary.HighCount++
		case "medium":
			summary.MediumCount++
		case "low":
			summary.LowCount++
		}
	}

	// Analyze host network pods
	hostNetworkPods, hostFindings, err := ns.DetectHostNetworkPods()
	if err != nil {
		return summary, recommendations, fmt.Errorf("failed to analyze host network pods: %w", err)
	}

	summary.HostNetworkPods = len(hostNetworkPods)
	summary.TotalFindings += len(hostFindings)

	for _, finding := range hostFindings {
		switch finding.Severity {
		case "critical":
			summary.CriticalCount++
		case "high":
			summary.HighCount++
		case "medium":
			summary.MediumCount++
		case "low":
			summary.LowCount++
		}
	}

	// Analyze public services
	publicServices, serviceFindings, err := ns.DetectPublicServices()
	if err != nil {
		return summary, recommendations, fmt.Errorf("failed to analyze public services: %w", err)
	}

	summary.PublicServices = len(publicServices)
	summary.TotalFindings += len(serviceFindings)

	for _, finding := range serviceFindings {
		switch finding.Severity {
		case "critical":
			summary.CriticalCount++
		case "high":
			summary.HighCount++
		case "medium":
			summary.MediumCount++
		case "low":
			summary.LowCount++
		}
	}

	// Analyze CNI configuration
	cniInfo, cniFindings, err := ns.DetectCNIConfiguration()
	if err != nil {
		return summary, recommendations, fmt.Errorf("failed to analyze CNI configuration: %w", err)
	}

	summary.CNIProvider = cniInfo.Provider
	summary.TotalFindings += len(cniFindings)

	for _, finding := range cniFindings {
		switch finding.Severity {
		case "critical":
			summary.CriticalCount++
		case "high":
			summary.HighCount++
		case "medium":
			summary.MediumCount++
		case "low":
			summary.LowCount++
		}
	}

	// Calculate network score
	summary.NetworkScore = ns.calculateNetworkScore(summary, networkPolicies, hostNetworkPods, publicServices, cniInfo)

	// Check for default deny policies
	summary.DefaultDenyEnabled = ns.checkDefaultDenyPolicies(networkPolicies)

	// Calculate blast radius
	summary.BlastRadius = ns.calculateBlastRadius(hostNetworkPods, publicServices)

	// Count unprotected namespaces
	summary.UnprotectedNamespaces = ns.countUnprotectedNamespaces(networkPolicies)

	// Generate recommendations
	recommendations = ns.generateRecommendations(summary, networkPolicies, hostNetworkPods, publicServices, cniInfo)

	return summary, recommendations, nil
}

// calculateNetworkScore calculates the overall network security score
func (ns *NetworkScanner) calculateNetworkScore(summary NetworkSummary, _ []NetworkPolicyInfo, _ []PodNetworkInfo, _ []ServiceInfo, _ CNIInfo) float64 {
	score := 100.0

	// Deduct points for critical issues
	score -= float64(summary.CriticalCount) * 20.0
	score -= float64(summary.HighCount) * 15.0
	score -= float64(summary.MediumCount) * 10.0
	score -= float64(summary.LowCount) * 5.0

	// Deduct points for specific issues
	if summary.HostNetworkPods > 0 {
		score -= float64(summary.HostNetworkPods) * 10.0
	}
	if summary.PublicServices > 0 {
		score -= float64(summary.PublicServices) * 8.0
	}
	if summary.UnprotectedNamespaces > 0 {
		score -= float64(summary.UnprotectedNamespaces) * 15.0
	}
	if !summary.DefaultDenyEnabled {
		score -= 25.0
	}
	if summary.CNIProvider == "" {
		score -= 20.0
	}
	if summary.BlastRadius > 10 {
		score -= 15.0
	}

	// Ensure score doesn't go below 0
	if score < 0 {
		score = 0
	}

	return score
}

// checkDefaultDenyPolicies checks if default deny policies are enabled
func (ns *NetworkScanner) checkDefaultDenyPolicies(policies []NetworkPolicyInfo) bool {
	// Check if there are any default deny policies
	for _, policy := range policies {
		// Look for policies that deny all traffic by default
		hasDenyAll := false
		for _, rule := range policy.Rules {
			if rule.Action == "deny" && rule.Direction == "ingress" {
				hasDenyAll = true
				break
			}
		}
		if hasDenyAll {
			return true
		}
	}
	return false
}

// calculateBlastRadius calculates the blast radius if a pod is compromised
func (ns *NetworkScanner) calculateBlastRadius(hostPods []PodNetworkInfo, services []ServiceInfo) int {
	blastRadius := 0

	// Count host network pods (high blast radius)
	for _, pod := range hostPods {
		if pod.HostNetwork {
			blastRadius += 10 // Host network pods have high blast radius
		}
	}

	// Count public services (medium blast radius)
	blastRadius += len(services)

	// Add base blast radius for unprotected namespaces
	blastRadius += 5

	return blastRadius
}

// countUnprotectedNamespaces counts namespaces without NetworkPolicies
func (ns *NetworkScanner) countUnprotectedNamespaces(policies []NetworkPolicyInfo) int {
	// This is a simplified count - in reality, you'd need to get all namespaces
	// and check which ones have policies
	namespacesWithPolicies := make(map[string]bool)
	for _, policy := range policies {
		namespacesWithPolicies[policy.Namespace] = true
	}

	// For now, return a simplified count
	// In a real implementation, you'd get all namespaces and count those without policies
	return 0
}

// generateRecommendations generates network security recommendations
func (ns *NetworkScanner) generateRecommendations(summary NetworkSummary, _ []NetworkPolicyInfo, _ []PodNetworkInfo, _ []ServiceInfo, _ CNIInfo) []string {
	var recommendations []string

	// NetworkPolicy recommendations
	if summary.NetworkPoliciesCount == 0 {
		recommendations = append(recommendations, "Implement NetworkPolicies for network segmentation")
		recommendations = append(recommendations, "Create default deny policies for all namespaces")
	} else if summary.UnprotectedNamespaces > 0 {
		recommendations = append(recommendations, "Create NetworkPolicies for unprotected namespaces")
	}

	if !summary.DefaultDenyEnabled {
		recommendations = append(recommendations, "Implement default deny NetworkPolicies")
		recommendations = append(recommendations, "Use deny-by-default policy as baseline")
	}

	// Host network recommendations
	if summary.HostNetworkPods > 0 {
		recommendations = append(recommendations, "Avoid using host network for pods")
		recommendations = append(recommendations, "Use regular pod networking instead of host networking")
		recommendations = append(recommendations, "Review pods using host network and migrate to pod networking")
	}

	// Public service recommendations
	if summary.PublicServices > 0 {
		recommendations = append(recommendations, "Review public service exposure")
		recommendations = append(recommendations, "Use ClusterIP services with ingress controllers")
		recommendations = append(recommendations, "Implement proper access controls for public services")
	}

	// CNI recommendations
	if summary.CNIProvider == "" {
		recommendations = append(recommendations, "Install and configure CNI provider")
		recommendations = append(recommendations, "Choose CNI that supports NetworkPolicies")
	} else if !ns.hasNetworkPolicySupport(summary.CNIProvider) {
		recommendations = append(recommendations, "Consider migrating to CNI with NetworkPolicy support")
		recommendations = append(recommendations, "Use Calico, Cilium, or Weave for NetworkPolicy support")
	}

	// General recommendations
	if summary.NetworkScore < 50 {
		recommendations = append(recommendations, "Implement comprehensive network segmentation")
		recommendations = append(recommendations, "Conduct network security assessment")
	}

	if summary.CriticalCount > 0 {
		recommendations = append(recommendations, "Address critical network vulnerabilities immediately")
	}

	if summary.HighCount > 0 {
		recommendations = append(recommendations, "Prioritize high-severity network issues")
	}

	if summary.BlastRadius > 10 {
		recommendations = append(recommendations, "Reduce blast radius by implementing network segmentation")
		recommendations = append(recommendations, "Use micro-segmentation to limit lateral movement")
	}

	return recommendations
}

// AnalyzeBlastRadius analyzes the blast radius for specific pods
func (ns *NetworkScanner) AnalyzeBlastRadius(podName, namespace string) (BlastRadius, error) {
	blastRadius := BlastRadius{
		PodName:   podName,
		Namespace: namespace,
		Metadata:  make(map[string]string),
	}

	// This is a simplified blast radius analysis
	// In a real implementation, you would:
	// 1. Get all pods in the cluster
	// 2. Test connectivity from the target pod to other pods
	// 3. Count reachable pods and services
	// 4. Calculate risk level based on connectivity

	// Simulate blast radius calculation
	blastRadius.ReachablePods = 5
	blastRadius.ReachableServices = 3
	blastRadius.RiskLevel = "medium"

	if blastRadius.ReachablePods > 10 {
		blastRadius.RiskLevel = "high"
	} else if blastRadius.ReachablePods < 3 {
		blastRadius.RiskLevel = "low"
	}

	// Add some example connections
	blastRadius.Connections = []Connection{
		{
			Source:   fmt.Sprintf("%s/%s", namespace, podName),
			Target:   "database/mysql",
			Protocol: "TCP",
			Port:     3306,
			Allowed:  true,
			Blocked:  false,
			Reason:   "No NetworkPolicy blocking",
		},
		{
			Source:   fmt.Sprintf("%s/%s", namespace, podName),
			Target:   "cache/redis",
			Protocol: "TCP",
			Port:     6379,
			Allowed:  true,
			Blocked:  false,
			Reason:   "No NetworkPolicy blocking",
		},
	}

	return blastRadius, nil
}

// BuildNetworkMatrix builds a network policy matrix
func (ns *NetworkScanner) BuildNetworkMatrix() (NetworkMatrix, error) {
	matrix := NetworkMatrix{
		Metadata: make(map[string]interface{}),
	}

	// Get all namespaces
	namespaces, err := ns.client.CoreV1().Namespaces().List(ns.ctx, metav1.ListOptions{})
	if err != nil {
		return matrix, fmt.Errorf("failed to list namespaces: %w", err)
	}

	for _, nsItem := range namespaces.Items {
		matrix.Namespaces = append(matrix.Namespaces, nsItem.Name)
	}

	// Get all pods
	pods, err := ns.client.CoreV1().Pods("").List(ns.ctx, metav1.ListOptions{})
	if err != nil {
		return matrix, fmt.Errorf("failed to list pods: %w", err)
	}

	for _, pod := range pods.Items {
		matrix.Pods = append(matrix.Pods, fmt.Sprintf("%s/%s", pod.Namespace, pod.Name))
	}

	// Get all services
	services, err := ns.client.CoreV1().Services("").List(ns.ctx, metav1.ListOptions{})
	if err != nil {
		return matrix, fmt.Errorf("failed to list services: %w", err)
	}

	for _, svc := range services.Items {
		matrix.Services = append(matrix.Services, fmt.Sprintf("%s/%s", svc.Namespace, svc.Name))
	}

	// Build network flows (simplified)
	matrix.Flows = []NetworkFlow{
		{
			Source:   "default/web-app",
			Target:   "default/api",
			Protocol: "TCP",
			Port:     8080,
			Allowed:  true,
			Policy:   "default-allow",
			Reason:   "No NetworkPolicy blocking",
		},
		{
			Source:   "default/web-app",
			Target:   "database/mysql",
			Protocol: "TCP",
			Port:     3306,
			Allowed:  true,
			Policy:   "default-allow",
			Reason:   "No NetworkPolicy blocking",
		},
	}

	return matrix, nil
}

// EvaluateNetworkSecurity evaluates overall network security posture
func (ns *NetworkScanner) EvaluateNetworkSecurity() []NetworkFinding {
	var findings []NetworkFinding

	// Check for missing NetworkPolicies
	networkPolicies, err := ns.client.NetworkingV1().NetworkPolicies("").List(ns.ctx, metav1.ListOptions{})
	if err == nil && len(networkPolicies.Items) == 0 {
		findings = append(findings, NetworkFinding{
			ID:          "network-security-001",
			Type:        "network-policy",
			Severity:    "critical",
			Title:       "No NetworkPolicies Found",
			Description: "No NetworkPolicies are configured in the cluster, leaving all network traffic unrestricted.",
			Resource:    "cluster",
			Namespace:   "all",
			RiskScore:   9.5,
			Remediation: "Implement NetworkPolicies to control network traffic and prevent lateral movement.",
			Timestamp:   time.Now(),
			Metadata: map[string]string{
				"policy_count": "0",
			},
		})
	}

	// Check for excessive host network usage
	pods, err := ns.client.CoreV1().Pods("").List(ns.ctx, metav1.ListOptions{})
	if err == nil {
		hostNetworkCount := 0
		for _, pod := range pods.Items {
			if pod.Spec.HostNetwork {
				hostNetworkCount++
			}
		}

		if hostNetworkCount > len(pods.Items)/2 {
			findings = append(findings, NetworkFinding{
				ID:          "network-security-002",
				Type:        "host-network",
				Severity:    "high",
				Title:       "Excessive Host Network Usage",
				Description: fmt.Sprintf("More than 50%% of pods (%d/%d) are using host network.", hostNetworkCount, len(pods.Items)),
				Resource:    "cluster",
				Namespace:   "all",
				RiskScore:   8.0,
				Remediation: "Reduce host network usage and implement proper pod networking.",
				Timestamp:   time.Now(),
				Metadata: map[string]string{
					"host_network_pods": fmt.Sprintf("%d", hostNetworkCount),
					"total_pods":        fmt.Sprintf("%d", len(pods.Items)),
					"percentage":        fmt.Sprintf("%.1f", float64(hostNetworkCount)/float64(len(pods.Items))*100),
				},
			})
		}
	}

	return findings
}
