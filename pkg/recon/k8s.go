package recon

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	authv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

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
func K8sRecon(ctx context.Context, kubeconfigPath string, stealth bool) error {
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
	nodes, err := clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		fmt.Printf("[!] Failed to list nodes: %v\n", err)
	} else {
		fmt.Printf("[+] Found %d nodes\n", len(nodes.Items))
		for _, node := range nodes.Items {
			fmt.Printf("    - %s\n", node.Name)
			if !stealth {
				// In non-stealth mode, get more node details
				fmt.Printf("      OS: %s\n", node.Status.NodeInfo.OSImage)
				fmt.Printf("      Kubelet: %s\n", node.Status.NodeInfo.KubeletVersion)
			}
		}
	}

	// Get namespaces
	namespaces, err := clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		fmt.Printf("[!] Failed to list namespaces: %v\n", err)
	} else {
		fmt.Printf("\n[+] Found %d namespaces\n", len(namespaces.Items))
		for _, ns := range namespaces.Items {
			fmt.Printf("    - %s\n", ns.Name)
			if !stealth {
				// List pods in namespace
				pods, err := clientset.CoreV1().Pods(ns.Name).List(ctx, metav1.ListOptions{})
				if err != nil {
					fmt.Printf("      [!] Failed to list pods: %v\n", err)
					continue
				}
				fmt.Printf("      Pods: %d\n", len(pods.Items))

				// Security checks for pods
				for _, pod := range pods.Items {
					for _, c := range pod.Spec.Containers {
						if pod.Spec.HostNetwork {
							fmt.Printf("      [!] Pod %s/%s uses hostNetwork\n", pod.Namespace, pod.Name)
						}
						if c.SecurityContext != nil {
							if c.SecurityContext.Privileged != nil && *c.SecurityContext.Privileged {
								fmt.Printf("      [!] Pod %s/%s container %s is privileged\n", pod.Namespace, pod.Name, c.Name)
							}
							if c.SecurityContext.AllowPrivilegeEscalation != nil && *c.SecurityContext.AllowPrivilegeEscalation {
								fmt.Printf("      [!] Pod %s/%s container %s allows privilege escalation\n", pod.Namespace, pod.Name, c.Name)
							}
							if c.SecurityContext.Capabilities != nil && len(c.SecurityContext.Capabilities.Add) > 0 {
								fmt.Printf("      [!] Pod %s/%s container %s adds capabilities: %v\n", pod.Namespace, pod.Name, c.Name, c.SecurityContext.Capabilities.Add)
							}
							if c.SecurityContext.RunAsUser != nil && *c.SecurityContext.RunAsUser == 0 {
								fmt.Printf("      [!] Pod %s/%s container %s runs as root\n", pod.Namespace, pod.Name, c.Name)
							}
						}
					}

					// Check for mounted secrets
					for _, vol := range pod.Spec.Volumes {
						if vol.Secret != nil {
							fmt.Printf("      [!] Pod %s/%s mounts secret: %s\n", pod.Namespace, pod.Name, vol.Secret.SecretName)
						}
					}
				}

				// Check Network Policies
				np, err := clientset.NetworkingV1().NetworkPolicies(ns.Name).List(ctx, metav1.ListOptions{})
				if err == nil && len(np.Items) == 0 {
					fmt.Printf("      [!] Namespace %s has no NetworkPolicies defined\n", ns.Name)
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
		fmt.Printf("[!] Failed to check permissions: %v\n", err)
	} else {
		if selfSAR.Status.Allowed {
			fmt.Println("\n[!] WARNING: Current user has cluster-admin privileges!")
		}
	}

	// Basic RBAC enumeration
	rbs, err := clientset.RbacV1().RoleBindings("").List(ctx, metav1.ListOptions{})
	if err != nil {
		fmt.Printf("[!] Failed to list role bindings: %v\n", err)
	} else {
		for _, rb := range rbs.Items {
			for _, s := range rb.Subjects {
				fmt.Printf("[i] RoleBinding %s binds %s/%s to role %s\n", rb.Name, s.Kind, s.Name, rb.RoleRef.Name)
			}
		}
	}

	crbs, err := clientset.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
	if err != nil {
		fmt.Printf("[!] Failed to list cluster role bindings: %v\n", err)
	} else {
		for _, crb := range crbs.Items {
			for _, s := range crb.Subjects {
				fmt.Printf("[i] ClusterRoleBinding %s binds %s/%s to role %s\n", crb.Name, s.Kind, s.Name, crb.RoleRef.Name)
			}
		}
	}

	return nil
}
