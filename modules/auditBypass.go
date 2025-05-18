package modules

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

var (
	auditPolicyPath       string
	auditBypassKubeConfig string

	// AuditBypassCmd represents the audit policy bypass analysis command
	AuditBypassCmd = &cobra.Command{
		Use:   "audit-bypass",
		Short: "Analyze and test Kubernetes audit policy bypasses",
		Long:  `Analyzes Kubernetes audit policies for weaknesses and simulates stealthy operations that might bypass audit logging`,
		Run: func(cmd *cobra.Command, args []string) {
			if err := AuditBypass(auditBypassKubeConfig, auditPolicyPath); err != nil {
				fmt.Printf("[-] Error during audit bypass analysis: %v\n", err)
			}
		},
	}
)

func init() {
	AuditBypassCmd.Flags().StringVar(&auditBypassKubeConfig, "kubeconfig", "", "Path to the kubeconfig file (required)")
	AuditBypassCmd.Flags().StringVar(&auditPolicyPath, "audit-policy", "", "Path to the audit policy file to analyze")
	AuditBypassCmd.MarkFlagRequired("kubeconfig")
}

type AuditPolicyRule struct {
	Level     string   `json:"level"`
	Users     []string `json:"users"`
	Verbs     []string `json:"verbs"`
	Resources []struct {
		Group     string   `json:"group"`
		Resources []string `json:"resources"`
	} `json:"resources"`
}

func loadKubeClient(kubeconfig string) (*kubernetes.Clientset, *rest.Config, error) {
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return nil, nil, err
	}
	clientset, err := kubernetes.NewForConfig(config)
	return clientset, config, err
}

// simulateBypass simulates a stealthy operation like exec or proxy with unusual verbs or subresources
func simulateBypass(clientset *kubernetes.Clientset) {
	fmt.Println("[] Simulating stealthy audit bypass behavior (e.g., 'GET' instead of 'exec')...")

	pods, err := clientset.CoreV1().Pods("kube-system").List(context.TODO(), metav1.ListOptions{})
	if err != nil || len(pods.Items) == 0 {
		fmt.Println("[-] No pods found for simulation.")
		return
	}

	pod := pods.Items[0]
	fmt.Printf("[+] Found pod: %s/%s\n", pod.Namespace, pod.Name)

	// Using GET on subresource exec may trigger fewer alerts if misconfigured
	url := fmt.Sprintf("/api/v1/namespaces/%s/pods/%s/exec?container=%s&command=ls&stdout=true", pod.Namespace, pod.Name, pod.Spec.Containers[0].Name)
	fmt.Printf("[>] Example stealth request:\nkubectl get --raw \"%s\"\n", url)
}

func AuditBypass(kubeconfig string, auditFilePath string) error {
	clientset, _, err := loadKubeClient(kubeconfig)
	if err != nil {
		return fmt.Errorf("failed to create client: %v", err)
	}

	// Step 1: If auditFilePath is passed, analyze audit policy
	if auditFilePath != "" {
		data, err := os.ReadFile(auditFilePath)
		if err != nil {
			return fmt.Errorf("could not read audit policy: %v", err)
		}

		var policy struct {
			Rules []AuditPolicyRule `json:"rules"`
		}
		if err := json.Unmarshal(data, &policy); err != nil {
			return fmt.Errorf("could not parse audit policy: %v", err)
		}

		fmt.Println("[+] Audit rules loaded. Looking for weaknesses...")
		for _, rule := range policy.Rules {
			if rule.Level == "Metadata" {
				fmt.Printf("[-] Rule logs only metadata (may miss sensitive info): %+v\n", rule)
			}
			if len(rule.Users) > 0 && !contains(rule.Users, "system:authenticated") {
				fmt.Printf("[!] Limited to specific users: %+v\n", rule.Users)
			}
		}
	}

	// Step 2: Simulate low-noise stealthy interactions
	simulateBypass(clientset)

	// Step 3: Enumerate users/roles that may bypass audit controls
	crbs, _ := clientset.RbacV1().ClusterRoleBindings().List(context.TODO(), metav1.ListOptions{})
	for _, crb := range crbs.Items {
		for _, subj := range crb.Subjects {
			if strings.Contains(subj.Name, "system:unauthenticated") || strings.Contains(subj.Name, "system:serviceaccount") {
				fmt.Printf("[?] Subject may be used to sneak operations: %s (Role: %s)\n", subj.Name, crb.RoleRef.Name)
			}
		}
	}

	return nil
}

func contains(arr []string, val string) bool {
	for _, s := range arr {
		if s == val {
			return true
		}
	}
	return false
}
