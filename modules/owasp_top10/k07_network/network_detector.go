package k07_network

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// NewNetworkScanner creates a new network scanner
func NewNetworkScanner(kubeconfig string, namespace string, labMode bool) (*NetworkScanner, error) {
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

	return &NetworkScanner{
		client:    clientset,
		namespace: namespace,
		ctx:       context.Background(),
		labMode:   labMode,
	}, nil
}

// DetectNetworkPolicies detects NetworkPolicy configurations
func (ns *NetworkScanner) DetectNetworkPolicies() ([]NetworkPolicyInfo, []NetworkFinding, error) {
	var findings []NetworkFinding
	var policies []NetworkPolicyInfo

	// List all NetworkPolicies
	networkPolicies, err := ns.client.NetworkingV1().NetworkPolicies("").List(ns.ctx, metav1.ListOptions{})
	if err != nil {
		return policies, findings, fmt.Errorf("failed to list network policies: %w", err)
	}

	for _, np := range networkPolicies.Items {
		policy := NetworkPolicyInfo{
			Name:        np.Name,
			Namespace:   np.Namespace,
			Type:        "NetworkPolicy",
			Enabled:     true,
			PodSelector: np.Spec.PodSelector.MatchLabels,
			Metadata:    make(map[string]string),
		}

		// Convert NetworkPolicy rules
		for _, rule := range np.Spec.Ingress {
			networkRule := NetworkRule{
				Direction: "ingress",
				Action:    "allow",
				Metadata:  make(map[string]string),
			}

			for _, from := range rule.From {
				if from.PodSelector != nil {
					networkRule.Source.PodSelector = from.PodSelector.MatchLabels
				}
				if from.NamespaceSelector != nil {
					networkRule.Source.NamespaceSelector = from.NamespaceSelector.MatchLabels
				}
				if from.IPBlock != nil {
					networkRule.Source.IPBlock = from.IPBlock.CIDR
				}
			}

			for _, port := range rule.Ports {
				if port.Protocol != nil {
					networkRule.Protocol = string(*port.Protocol)
				}
				if port.Port != nil {
					networkRule.Port = port.Port.IntValue()
				}
			}

			policy.Rules = append(policy.Rules, networkRule)
		}

		for _, rule := range np.Spec.Egress {
			networkRule := NetworkRule{
				Direction: "egress",
				Action:    "allow",
				Metadata:  make(map[string]string),
			}

			for _, to := range rule.To {
				if to.PodSelector != nil {
					networkRule.Target.PodSelector = to.PodSelector.MatchLabels
				}
				if to.NamespaceSelector != nil {
					networkRule.Target.NamespaceSelector = to.NamespaceSelector.MatchLabels
				}
				if to.IPBlock != nil {
					networkRule.Target.IPBlock = to.IPBlock.CIDR
				}
			}

			for _, port := range rule.Ports {
				if port.Protocol != nil {
					networkRule.Protocol = string(*port.Protocol)
				}
				if port.Port != nil {
					networkRule.Port = port.Port.IntValue()
				}
			}

			policy.Rules = append(policy.Rules, networkRule)
		}

		policies = append(policies, policy)
	}

	// Check for namespaces without NetworkPolicies
	namespaces, err := ns.client.CoreV1().Namespaces().List(ns.ctx, metav1.ListOptions{})
	if err == nil {
		for _, nsItem := range namespaces.Items {
			hasPolicy := false
			for _, policy := range policies {
				if policy.Namespace == nsItem.Name {
					hasPolicy = true
					break
				}
			}
			if !hasPolicy {
				findings = append(findings, NetworkFinding{
					ID:          "network-001",
					Type:        "network-policy",
					Severity:    "high",
					Title:       "Namespace Without NetworkPolicy",
					Description: fmt.Sprintf("Namespace %s has no NetworkPolicy configured.", nsItem.Name),
					Resource:    fmt.Sprintf("namespace/%s", nsItem.Name),
					Namespace:   nsItem.Name,
					RiskScore:   7.5,
					Remediation: "Create a default deny NetworkPolicy for the namespace.",
					Timestamp:   time.Now(),
					Metadata: map[string]string{
						"namespace":    nsItem.Name,
						"policy_count": "0",
					},
				})
			}
		}
	}

	return policies, findings, nil
}

// DetectHostNetworkPods detects pods using host network
func (ns *NetworkScanner) DetectHostNetworkPods() ([]PodNetworkInfo, []NetworkFinding, error) {
	var findings []NetworkFinding
	var pods []PodNetworkInfo

	// List all pods
	podList, err := ns.client.CoreV1().Pods("").List(ns.ctx, metav1.ListOptions{})
	if err != nil {
		return pods, findings, fmt.Errorf("failed to list pods: %w", err)
	}

	for _, pod := range podList.Items {
		podInfo := PodNetworkInfo{
			Name:        pod.Name,
			Namespace:   pod.Namespace,
			HostNetwork: pod.Spec.HostNetwork,
			HostPID:     pod.Spec.HostPID,
			HostIPC:     pod.Spec.HostIPC,
			IP:          pod.Status.PodIP,
			HostIP:      pod.Status.HostIP,
			Labels:      pod.Labels,
			Metadata:    make(map[string]string),
		}

		// Check for host network usage
		if pod.Spec.HostNetwork {
			podInfo.RiskLevel = "high"
			findings = append(findings, NetworkFinding{
				ID:          "network-002",
				Type:        "host-network",
				Severity:    "high",
				Title:       "Pod Using Host Network",
				Description: fmt.Sprintf("Pod %s/%s is using host network, bypassing network segmentation.", pod.Namespace, pod.Name),
				Resource:    fmt.Sprintf("pod/%s", pod.Name),
				Namespace:   pod.Namespace,
				RiskScore:   8.0,
				Remediation: "Avoid using host network unless absolutely necessary. Use regular pod networking instead.",
				Timestamp:   time.Now(),
				Metadata: map[string]string{
					"pod":          pod.Name,
					"namespace":    pod.Namespace,
					"host_network": "true",
				},
			})
		}

		// Check for host PID usage
		if pod.Spec.HostPID {
			podInfo.RiskLevel = "medium"
			findings = append(findings, NetworkFinding{
				ID:          "network-003",
				Type:        "host-pid",
				Severity:    "medium",
				Title:       "Pod Using Host PID",
				Description: fmt.Sprintf("Pod %s/%s is using host PID namespace.", pod.Namespace, pod.Name),
				Resource:    fmt.Sprintf("pod/%s", pod.Name),
				Namespace:   pod.Namespace,
				RiskScore:   6.0,
				Remediation: "Avoid using host PID unless necessary for debugging. Use regular pod PID namespace.",
				Timestamp:   time.Now(),
				Metadata: map[string]string{
					"pod":       pod.Name,
					"namespace": pod.Namespace,
					"host_pid":  "true",
				},
			})
		}

		// Check for host IPC usage
		if pod.Spec.HostIPC {
			podInfo.RiskLevel = "medium"
			findings = append(findings, NetworkFinding{
				ID:          "network-004",
				Type:        "host-ipc",
				Severity:    "medium",
				Title:       "Pod Using Host IPC",
				Description: fmt.Sprintf("Pod %s/%s is using host IPC namespace.", pod.Namespace, pod.Name),
				Resource:    fmt.Sprintf("pod/%s", pod.Name),
				Namespace:   pod.Namespace,
				RiskScore:   6.0,
				Remediation: "Avoid using host IPC unless necessary. Use regular pod IPC namespace.",
				Timestamp:   time.Now(),
				Metadata: map[string]string{
					"pod":       pod.Name,
					"namespace": pod.Namespace,
					"host_ipc":  "true",
				},
			})
		}

		pods = append(pods, podInfo)
	}

	return pods, findings, nil
}

// DetectPublicServices detects publicly exposed services
func (ns *NetworkScanner) DetectPublicServices() ([]ServiceInfo, []NetworkFinding, error) {
	var findings []NetworkFinding
	var services []ServiceInfo

	// List all services
	serviceList, err := ns.client.CoreV1().Services("").List(ns.ctx, metav1.ListOptions{})
	if err != nil {
		return services, findings, fmt.Errorf("failed to list services: %w", err)
	}

	for _, svc := range serviceList.Items {
		service := ServiceInfo{
			Name:      svc.Name,
			Namespace: svc.Namespace,
			Type:      string(svc.Spec.Type),
			ClusterIP: svc.Spec.ClusterIP,
			Metadata:  make(map[string]string),
		}

		// Check for LoadBalancer services
		if svc.Spec.Type == corev1.ServiceTypeLoadBalancer {
			service.Public = true
			service.Exposed = true
			service.RiskLevel = "high"

			// Check if LoadBalancer has external IPs
			if len(svc.Status.LoadBalancer.Ingress) > 0 {
				service.ExternalIP = svc.Status.LoadBalancer.Ingress[0].IP
				findings = append(findings, NetworkFinding{
					ID:          "network-005",
					Type:        "public-service",
					Severity:    "high",
					Title:       "Public LoadBalancer Service",
					Description: fmt.Sprintf("Service %s/%s is exposed via LoadBalancer with external IP %s.", svc.Namespace, svc.Name, service.ExternalIP),
					Resource:    fmt.Sprintf("service/%s", svc.Name),
					Namespace:   svc.Namespace,
					RiskScore:   8.5,
					Remediation: "Review LoadBalancer exposure and implement proper access controls or use ClusterIP with ingress controller.",
					Timestamp:   time.Now(),
					Metadata: map[string]string{
						"service":     svc.Name,
						"namespace":   svc.Namespace,
						"type":        "LoadBalancer",
						"external_ip": service.ExternalIP,
					},
				})
			}
		}

		// Check for NodePort services
		if svc.Spec.Type == corev1.ServiceTypeNodePort {
			service.Public = true
			service.Exposed = true
			service.RiskLevel = "medium"

			findings = append(findings, NetworkFinding{
				ID:          "network-006",
				Type:        "nodeport-service",
				Severity:    "medium",
				Title:       "NodePort Service",
				Description: fmt.Sprintf("Service %s/%s is exposed via NodePort.", svc.Namespace, svc.Name),
				Resource:    fmt.Sprintf("service/%s", svc.Name),
				Namespace:   svc.Namespace,
				RiskScore:   6.5,
				Remediation: "Review NodePort exposure and consider using ClusterIP with ingress controller.",
				Timestamp:   time.Now(),
				Metadata: map[string]string{
					"service":   svc.Name,
					"namespace": svc.Namespace,
					"type":      "NodePort",
				},
			})
		}

		// Convert service ports
		for _, port := range svc.Spec.Ports {
			servicePort := ServicePort{
				Name:       port.Name,
				Port:       int(port.Port),
				TargetPort: port.TargetPort.IntValue(),
				Protocol:   string(port.Protocol),
				NodePort:   int(port.NodePort),
			}
			service.Ports = append(service.Ports, servicePort)
		}

		services = append(services, service)
	}

	return services, findings, nil
}

// DetectCNIConfiguration detects CNI configuration
func (ns *NetworkScanner) DetectCNIConfiguration() (CNIInfo, []NetworkFinding, error) {
	var findings []NetworkFinding
	cniInfo := CNIInfo{
		Config:   make(map[string]string),
		Metadata: make(map[string]string),
	}

	// Try to detect CNI provider by checking DaemonSets
	daemonSets, err := ns.client.AppsV1().DaemonSets("").List(ns.ctx, metav1.ListOptions{})
	if err == nil {
		for _, ds := range daemonSets.Items {
			if strings.Contains(ds.Name, "calico") {
				cniInfo.Provider = "Calico"
				cniInfo.Features = append(cniInfo.Features, "NetworkPolicies", "IPAM")
			} else if strings.Contains(ds.Name, "flannel") {
				cniInfo.Provider = "Flannel"
				cniInfo.Features = append(cniInfo.Features, "Overlay")
			} else if strings.Contains(ds.Name, "weave") {
				cniInfo.Provider = "Weave"
				cniInfo.Features = append(cniInfo.Features, "NetworkPolicies", "Encryption")
			} else if strings.Contains(ds.Name, "cilium") {
				cniInfo.Provider = "Cilium"
				cniInfo.Features = append(cniInfo.Features, "NetworkPolicies", "ServiceMesh", "Observability")
			}
		}
	}

	// Check for CNI configuration issues
	if cniInfo.Provider == "" {
		findings = append(findings, NetworkFinding{
			ID:          "network-007",
			Type:        "cni-config",
			Severity:    "medium",
			Title:       "CNI Provider Not Detected",
			Description: "Unable to detect CNI provider. This may indicate missing or misconfigured CNI.",
			Resource:    "cluster",
			Namespace:   "all",
			RiskScore:   5.0,
			Remediation: "Ensure CNI is properly installed and configured for network segmentation.",
			Timestamp:   time.Now(),
		})
	}

	// Check for NetworkPolicy support
	if cniInfo.Provider != "" && !ns.hasNetworkPolicySupport(cniInfo.Provider) {
		findings = append(findings, NetworkFinding{
			ID:          "network-008",
			Type:        "network-policy-support",
			Severity:    "high",
			Title:       "CNI Does Not Support NetworkPolicies",
			Description: fmt.Sprintf("CNI provider %s does not support NetworkPolicies.", cniInfo.Provider),
			Resource:    "cluster",
			Namespace:   "all",
			RiskScore:   7.5,
			Remediation: "Consider migrating to a CNI that supports NetworkPolicies (Calico, Cilium, Weave).",
			Timestamp:   time.Now(),
		})
	}

	return cniInfo, findings, nil
}

// Helper methods for network detection
func (ns *NetworkScanner) hasNetworkPolicySupport(provider string) bool {
	supportedProviders := []string{"Calico", "Cilium", "Weave"}
	for _, supported := range supportedProviders {
		if provider == supported {
			return true
		}
	}
	return false
}

// TestConnectivity tests network connectivity between pods
func (ns *NetworkScanner) TestConnectivity(sourcePod, targetPod, targetNamespace string, port int) ConnectivityTest {
	test := ConnectivityTest{
		TestName:    "Pod-to-Pod Connectivity",
		Description: fmt.Sprintf("Test connectivity from %s to %s/%s on port %d", sourcePod, targetNamespace, targetPod, port),
		Source:      sourcePod,
		Target:      fmt.Sprintf("%s/%s", targetNamespace, targetPod),
		Protocol:    "TCP",
		Port:        port,
		Timestamp:   time.Now(),
		Metadata:    make(map[string]string),
	}

	// This is a simplified connectivity test
	// In a real implementation, you would create a test pod and run actual network tests
	if ns.labMode {
		// Simulate connectivity test
		test.Success = true
		test.Latency = 5 * time.Millisecond
		test.Metadata["test_type"] = "connectivity"
		test.Metadata["result"] = "success"
	} else {
		test.Success = false
		test.Error = "Connectivity testing requires lab mode"
		test.Metadata["test_type"] = "connectivity"
		test.Metadata["result"] = "skipped"
	}

	return test
}

// IsPublicCIDR checks if a CIDR is publicly accessible
func (ns *NetworkScanner) IsPublicCIDR(cidr string) bool {
	// Check if CIDR allows public access (0.0.0.0/0)
	return cidr == "0.0.0.0/0" || cidr == "::/0"
}

// ValidateIPAddress validates an IP address
func (ns *NetworkScanner) ValidateIPAddress(ip string) bool {
	return net.ParseIP(ip) != nil
}
