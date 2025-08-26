package recon

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"kubeshadow/pkg/errors"

	authv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

// ReconClient handles Kubernetes reconnaissance operations
type ReconClient struct {
	clientset *kubernetes.Clientset
}

// NewReconClient creates a new ReconClient instance
func NewReconClient() (*ReconClient, error) {
	kubeconfig := filepath.Join(os.Getenv("HOME"), ".kube", "config")
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return nil, errors.New(errors.ErrK8s, "failed to build kubeconfig", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, errors.New(errors.ErrK8s, "failed to create kubernetes client", err)
	}

	return &ReconClient{clientset: clientset}, nil
}

// ListPods lists all pods in the specified namespace
func (c *ReconClient) ListPods(ctx context.Context, namespace string) ([]corev1.Pod, error) {
	pods, err := c.clientset.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, errors.New(errors.ErrK8s, fmt.Sprintf("failed to list pods in namespace %s", namespace), err)
	}
	return pods.Items, nil
}

// ListServices lists all services in the specified namespace
func (c *ReconClient) ListServices(ctx context.Context, namespace string) ([]corev1.Service, error) {
	services, err := c.clientset.CoreV1().Services(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, errors.New(errors.ErrK8s, fmt.Sprintf("failed to list services in namespace %s", namespace), err)
	}
	return services.Items, nil
}

// ListSecrets lists all secrets in the specified namespace
func (c *ReconClient) ListSecrets(ctx context.Context, namespace string) ([]corev1.Secret, error) {
	secrets, err := c.clientset.CoreV1().Secrets(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, errors.New(errors.ErrK8s, fmt.Sprintf("failed to list secrets in namespace %s", namespace), err)
	}
	return secrets.Items, nil
}

// ListConfigMaps lists all configmaps in the specified namespace
func (c *ReconClient) ListConfigMaps(ctx context.Context, namespace string) ([]corev1.ConfigMap, error) {
	configmaps, err := c.clientset.CoreV1().ConfigMaps(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, errors.New(errors.ErrK8s, fmt.Sprintf("failed to list configmaps in namespace %s", namespace), err)
	}
	return configmaps.Items, nil
}

// ListNamespaces lists all namespaces
func (c *ReconClient) ListNamespaces(ctx context.Context) ([]corev1.Namespace, error) {
	namespaces, err := c.clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, errors.New(errors.ErrK8s, "failed to list namespaces", err)
	}
	return namespaces.Items, nil
}

// GetPodLogs retrieves logs for a specific pod
func (c *ReconClient) GetPodLogs(ctx context.Context, namespace, podName string) (string, error) {
	req := c.clientset.CoreV1().Pods(namespace).GetLogs(podName, &corev1.PodLogOptions{})
	logs, err := req.Do(ctx).Raw()
	if err != nil {
		return "", errors.New(errors.ErrK8s, fmt.Sprintf("failed to get logs for pod %s", podName), err)
	}
	return string(logs), nil
}

// GetPodEvents retrieves events for a specific pod
func (c *ReconClient) GetPodEvents(ctx context.Context, namespace, podName string) ([]corev1.Event, error) {
	events, err := c.clientset.CoreV1().Events(namespace).List(ctx, metav1.ListOptions{
		FieldSelector: fmt.Sprintf("involvedObject.name=%s", podName),
	})
	if err != nil {
		return nil, errors.New(errors.ErrK8s, fmt.Sprintf("failed to get events for pod %s", podName), err)
	}
	return events.Items, nil
}

// GetNodeInfo retrieves information about a specific node
func (c *ReconClient) GetNodeInfo(ctx context.Context, nodeName string) (*corev1.Node, error) {
	node, err := c.clientset.CoreV1().Nodes().Get(ctx, nodeName, metav1.GetOptions{})
	if err != nil {
		return nil, errors.New(errors.ErrK8s, fmt.Sprintf("failed to get node %s", nodeName), err)
	}
	return node, nil
}

// GetPodInfo retrieves detailed information about a specific pod
func (c *ReconClient) GetPodInfo(ctx context.Context, namespace, podName string) (*corev1.Pod, error) {
	pod, err := c.clientset.CoreV1().Pods(namespace).Get(ctx, podName, metav1.GetOptions{})
	if err != nil {
		return nil, errors.New(errors.ErrK8s, fmt.Sprintf("failed to get pod %s", podName), err)
	}
	return pod, nil
}

// GetServiceInfo retrieves detailed information about a specific service
func (c *ReconClient) GetServiceInfo(ctx context.Context, namespace, serviceName string) (*corev1.Service, error) {
	service, err := c.clientset.CoreV1().Services(namespace).Get(ctx, serviceName, metav1.GetOptions{})
	if err != nil {
		return nil, errors.New(errors.ErrK8s, fmt.Sprintf("failed to get service %s", serviceName), err)
	}
	return service, nil
}

// checkCoreDNSConfig looks for potential DNS cache poisoning vectors
func checkCoreDNSConfig(clientset *kubernetes.Clientset, ctx context.Context) {
	fmt.Println("\n[*] Checking CoreDNS configuration...")
	cm, err := clientset.CoreV1().ConfigMaps("kube-system").Get(ctx, "coredns", metav1.GetOptions{})
	if err != nil {
		fmt.Println("[-] Could not find CoreDNS configmap")
		return
	}

	data := cm.Data["Corefile"]
	if strings.Contains(data, "rewrite") || strings.Contains(data, "template") {
		fmt.Println("[!] CoreDNS config contains rewrite/template logic - potential DNS spoofing vector")
	}
	if strings.Contains(data, "fallthrough") {
		fmt.Println("[!] CoreDNS config has fallthrough - may allow wildcard shadowing")
	}
}

// checkCloudMetadataAccess checks for potential access to cloud metadata services
func checkCloudMetadataAccess(clientset *kubernetes.Clientset, ctx context.Context, ns string) {
	pods, err := clientset.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return
	}

	for _, pod := range pods.Items {
		// Check for host network mode which might allow metadata service access
		if pod.Spec.HostNetwork {
			fmt.Printf("[!] Pod %s/%s uses host network - potential cloud metadata service access\n", ns, pod.Name)
		}

		// Check for environment variables that might indicate cloud environment
		for _, container := range pod.Spec.Containers {
			for _, env := range container.Env {
				if strings.Contains(strings.ToLower(env.Name), "aws") ||
					strings.Contains(strings.ToLower(env.Name), "azure") ||
					strings.Contains(strings.ToLower(env.Name), "gcp") {
					fmt.Printf("[!] Pod %s/%s container %s has cloud-related env var: %s\n",
						ns, pod.Name, container.Name, env.Name)
				}
			}
		}
	}
}

// checkNamespacePivot checks for potential namespace pivot opportunities
func checkNamespacePivot(clientset *kubernetes.Clientset, ctx context.Context, ns string) {
	// Check for service accounts with elevated permissions
	sas, err := clientset.CoreV1().ServiceAccounts(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return
	}

	for _, sa := range sas.Items {
		// Check if SA has any secrets (tokens)
		if len(sa.Secrets) > 0 {
			fmt.Printf("[*] ServiceAccount %s/%s has associated tokens\n", ns, sa.Name)
		}
	}

	// Check for role bindings that might allow pivoting
	rbs, _ := clientset.RbacV1().RoleBindings(ns).List(ctx, metav1.ListOptions{})
	for _, rb := range rbs.Items {
		if strings.Contains(rb.RoleRef.Name, "admin") || strings.Contains(rb.RoleRef.Name, "cluster") {
			fmt.Printf("[!] RoleBinding %s/%s grants elevated permissions (%s)\n", ns, rb.Name, rb.RoleRef.Name)
		}
	}
}

// K8sRecon performs Kubernetes API reconnaissance
func K8sRecon(ctx context.Context, kubeconfigPath string, stealth bool, showRBAC bool) error {
	// Expand ~ to home directory if present
	if kubeconfigPath == "~/.kube/config" {
		home := homedir.HomeDir()
		kubeconfigPath = filepath.Join(home, ".kube", "config")
	}

	// Create k8s client
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfigPath)
	if err != nil {
		return fmt.Errorf("failed to load kubeconfig: %v", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("failed to create k8s client: %v", err)
	}

	// Get nodes
	fmt.Printf("\n🔍 NODE DISCOVERY\n")
	fmt.Printf("─" + strings.Repeat("─", 50) + "\n")
	nodes, err := clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		fmt.Printf("❌ Failed to list nodes: %v\n", err)
	} else {
		fmt.Printf("✅ Found %d nodes\n", len(nodes.Items))
		for _, node := range nodes.Items {
			fmt.Printf("   • %s\n", node.Name)
			if !stealth {
				// In non-stealth mode, get more node details
				fmt.Printf("     OS: %s\n", node.Status.NodeInfo.OSImage)
				fmt.Printf("     Kubelet: %s\n", node.Status.NodeInfo.KubeletVersion)
			}
		}
	}

	// Get namespaces
	fmt.Printf("\n📁 NAMESPACE ANALYSIS\n")
	fmt.Printf(strings.Repeat("─", 30) + "\n")
	namespaces, err := clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		fmt.Printf("❌ Failed to list namespaces: %v\n", err)
	} else {
		fmt.Printf("✅ Found %d namespaces\n", len(namespaces.Items))
		for _, ns := range namespaces.Items {
			fmt.Printf("   • %s\n", ns.Name)
			if !stealth {
				// List pods in namespace
				pods, err := clientset.CoreV1().Pods(ns.Name).List(ctx, metav1.ListOptions{})
				if err != nil {
					fmt.Printf("     ❌ Failed to list pods: %v\n", err)
					continue
				}
				fmt.Printf("     Pods: %d\n", len(pods.Items))

				// Security checks for pods
				for _, pod := range pods.Items {
					for _, c := range pod.Spec.Containers {
						if pod.Spec.HostNetwork {
							fmt.Printf("     ⚠️  Pod %s/%s uses hostNetwork\n", pod.Namespace, pod.Name)
						}
						if c.SecurityContext != nil {
							if c.SecurityContext.Privileged != nil && *c.SecurityContext.Privileged {
								fmt.Printf("     🔴 Pod %s/%s container %s is privileged\n", pod.Namespace, pod.Name, c.Name)
							}
							if c.SecurityContext.AllowPrivilegeEscalation != nil && *c.SecurityContext.AllowPrivilegeEscalation {
								fmt.Printf("     🟡 Pod %s/%s container %s allows privilege escalation\n", pod.Namespace, pod.Name, c.Name)
							}
							if c.SecurityContext.Capabilities != nil && len(c.SecurityContext.Capabilities.Add) > 0 {
								fmt.Printf("     🟠 Pod %s/%s container %s adds capabilities: %v\n", pod.Namespace, pod.Name, c.Name, c.SecurityContext.Capabilities.Add)
							}
							if c.SecurityContext.RunAsUser != nil && *c.SecurityContext.RunAsUser == 0 {
								fmt.Printf("     🔴 Pod %s/%s container %s runs as root\n", pod.Namespace, pod.Name, c.Name)
							}
						}
					}

					// Check for mounted secrets
					for _, vol := range pod.Spec.Volumes {
						if vol.Secret != nil {
							fmt.Printf("     🔐 Pod %s/%s mounts secret: %s\n", pod.Namespace, pod.Name, vol.Secret.SecretName)
						}
					}
				}

				// Check Network Policies
				np, err := clientset.NetworkingV1().NetworkPolicies(ns.Name).List(ctx, metav1.ListOptions{})
				if err == nil && len(np.Items) == 0 {
					fmt.Printf("     🚨 Namespace %s has no NetworkPolicies defined\n", ns.Name)
				}

				// List services in namespace
				services, err := clientset.CoreV1().Services(ns.Name).List(ctx, metav1.ListOptions{})
				if err != nil {
					fmt.Printf("     ❌ Failed to list services: %v\n", err)
				} else if len(services.Items) > 0 {
					fmt.Printf("     Services: %d\n", len(services.Items))
					for _, svc := range services.Items {
						svcType := string(svc.Spec.Type)
						externalIP := "<none>"
						if svc.Spec.ExternalIPs != nil && len(svc.Spec.ExternalIPs) > 0 {
							externalIP = svc.Spec.ExternalIPs[0]
						} else if svc.Spec.LoadBalancerIP != "" {
							externalIP = svc.Spec.LoadBalancerIP
						} else if svc.Status.LoadBalancer.Ingress != nil && len(svc.Status.LoadBalancer.Ingress) > 0 {
							externalIP = svc.Status.LoadBalancer.Ingress[0].IP
						}

						if externalIP != "<none>" {
							fmt.Printf("       🔴 Service %s/%s (%s) - EXTERNAL IP: %s\n", svc.Namespace, svc.Name, svcType, externalIP)
						} else {
							fmt.Printf("       • Service %s/%s (%s)\n", svc.Namespace, svc.Name, svcType)
						}
					}
				}

				// List secrets in namespace
				secrets, err := clientset.CoreV1().Secrets(ns.Name).List(ctx, metav1.ListOptions{})
				if err != nil {
					fmt.Printf("     ❌ Failed to list secrets: %v\n", err)
				} else if len(secrets.Items) > 0 {
					fmt.Printf("     Secrets: %d\n", len(secrets.Items))
					for _, secret := range secrets.Items {
						secretType := string(secret.Type)
						dataCount := len(secret.Data)
						fmt.Printf("       🔴 Secret %s/%s (%s) - %d keys\n", secret.Namespace, secret.Name, secretType, dataCount)

						// Check for sensitive secret types
						if secretType == "kubernetes.io/service-account-token" {
							fmt.Printf("         ⚠️  ServiceAccount token found!\n")
						} else if secretType == "kubernetes.io/dockerconfigjson" {
							fmt.Printf("         ⚠️  Docker registry credentials found!\n")
						} else if secretType == "kubernetes.io/tls" {
							fmt.Printf("         ⚠️  TLS certificate found!\n")
						}
					}
				}

				// List configmaps in namespace
				configmaps, err := clientset.CoreV1().ConfigMaps(ns.Name).List(ctx, metav1.ListOptions{})
				if err != nil {
					fmt.Printf("     ❌ Failed to list configmaps: %v\n", err)
				} else if len(configmaps.Items) > 0 {
					fmt.Printf("     ConfigMaps: %d\n", len(configmaps.Items))
					for _, cm := range configmaps.Items {
						dataCount := len(cm.Data)
						fmt.Printf("       • ConfigMap %s/%s - %d keys\n", cm.Namespace, cm.Name, dataCount)
					}
				}

				// Additional security checks
				checkCloudMetadataAccess(clientset, ctx, ns.Name)
				checkNamespacePivot(clientset, ctx, ns.Name)
			}
		}
	}

	// Add CoreDNS check
	if !stealth {
		checkCoreDNSConfig(clientset, ctx)
	}

	// Check RBAC permissions
	selfSAR, err := clientset.AuthorizationV1().SelfSubjectAccessReviews().Create(ctx, &authv1.SelfSubjectAccessReview{
		Spec: authv1.SelfSubjectAccessReviewSpec{
			ResourceAttributes: &authv1.ResourceAttributes{
				Verb:     "*",
				Resource: "*",
			},
		},
	}, metav1.CreateOptions{})
	if err != nil {
		fmt.Printf("❌ Failed to check permissions: %v\n", err)
	} else {
		if selfSAR.Status.Allowed {
			fmt.Println("\n🔴 WARNING: Current user has cluster-admin privileges!")
		}
	}

	// RBAC enumeration (conditional)
	if showRBAC {
		fmt.Printf("\n🔐 RBAC ANALYSIS\n")
		fmt.Printf(strings.Repeat("─", 30) + "\n")

		// Basic RBAC enumeration
		rbs, err := clientset.RbacV1().RoleBindings("").List(ctx, metav1.ListOptions{})
		if err != nil {
			fmt.Printf("❌ Failed to list role bindings: %v\n", err)
		} else {
			fmt.Printf("RoleBindings (%d found):\n", len(rbs.Items))
			for _, rb := range rbs.Items {
				for _, s := range rb.Subjects {
					fmt.Printf("   • %s binds %s/%s to role %s\n", rb.Name, s.Kind, s.Name, rb.RoleRef.Name)
				}
			}
		}

		crbs, err := clientset.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
		if err != nil {
			fmt.Printf("❌ Failed to list cluster role bindings: %v\n", err)
		} else {
			fmt.Printf("\nClusterRoleBindings (%d found):\n", len(crbs.Items))
			for _, crb := range crbs.Items {
				for _, s := range crb.Subjects {
					fmt.Printf("   • %s binds %s/%s to role %s\n", crb.Name, s.Kind, s.Name, crb.RoleRef.Name)
				}
			}
		}
	}

	// Enhanced reconnaissance summary
	if !stealth {
		fmt.Printf("\n" + strings.Repeat("=", 60) + "\n")
		fmt.Printf("🎯 ENHANCED RECONNAISSANCE SUMMARY\n")
		fmt.Printf(strings.Repeat("=", 60) + "\n")

		// Get total counts
		allPods, _ := clientset.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
		allServices, _ := clientset.CoreV1().Services("").List(ctx, metav1.ListOptions{})
		allSecrets, _ := clientset.CoreV1().Secrets("").List(ctx, metav1.ListOptions{})
		allConfigMaps, _ := clientset.CoreV1().ConfigMaps("").List(ctx, metav1.ListOptions{})

		fmt.Printf("📊 CLUSTER OVERVIEW:\n")
		fmt.Printf("   Nodes: %d\n", len(nodes.Items))
		fmt.Printf("   Namespaces: %d\n", len(namespaces.Items))
		fmt.Printf("   Total Pods: %d\n", len(allPods.Items))
		fmt.Printf("   Total Services: %d\n", len(allServices.Items))
		fmt.Printf("   Total Secrets: %d\n", len(allSecrets.Items))
		fmt.Printf("   Total ConfigMaps: %d\n", len(allConfigMaps.Items))

		// Security findings summary
		fmt.Printf("\n🚨 SECURITY FINDINGS:\n")

		// Count external services
		externalServices := 0
		for _, svc := range allServices.Items {
			if svc.Spec.Type == corev1.ServiceTypeLoadBalancer ||
				(svc.Spec.ExternalIPs != nil && len(svc.Spec.ExternalIPs) > 0) ||
				(svc.Status.LoadBalancer.Ingress != nil && len(svc.Status.LoadBalancer.Ingress) > 0) {
				externalServices++
			}
		}
		if externalServices > 0 {
			fmt.Printf("   🔴 %d externally exposed services\n", externalServices)
		}

		// Count privileged containers
		privilegedContainers := 0
		for _, pod := range allPods.Items {
			for _, c := range pod.Spec.Containers {
				if c.SecurityContext != nil && c.SecurityContext.Privileged != nil && *c.SecurityContext.Privileged {
					privilegedContainers++
				}
			}
		}
		if privilegedContainers > 0 {
			fmt.Printf("   🔴 %d privileged containers\n", privilegedContainers)
		}

		// Count secrets with sensitive types
		sensitiveSecrets := 0
		for _, secret := range allSecrets.Items {
			secretType := string(secret.Type)
			if secretType == "kubernetes.io/service-account-token" ||
				secretType == "kubernetes.io/dockerconfigjson" ||
				secretType == "kubernetes.io/tls" {
				sensitiveSecrets++
			}
		}
		if sensitiveSecrets > 0 {
			fmt.Printf("   🔐 %d sensitive secrets (tokens, registry creds, TLS)\n", sensitiveSecrets)
		}

		// Network policy check
		namespacesWithoutNP := 0
		for _, ns := range namespaces.Items {
			np, _ := clientset.NetworkingV1().NetworkPolicies(ns.Name).List(ctx, metav1.ListOptions{})
			if len(np.Items) == 0 {
				namespacesWithoutNP++
			}
		}
		if namespacesWithoutNP > 0 {
			fmt.Printf("   🚨 %d namespaces without NetworkPolicies\n", namespacesWithoutNP)
		}

		fmt.Printf(strings.Repeat("=", 60) + "\n")
	}

	return nil
}
