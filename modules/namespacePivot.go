package modules

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/spf13/cobra"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8s "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

var (
	namespacePivotKubeConfig string

	// NamespacePivotCmd represents the namespace pivoting command
	NamespacePivotCmd = &cobra.Command{
		Use:   "namespace-pivot",
		Short: "Analyze namespace isolation and pivot opportunities",
		Long:  `Enumerates service accounts, RBAC bindings, and tokens across namespaces to identify potential pivot vectors`,
		Run: func(cmd *cobra.Command, args []string) {
			if err := NamespacePivot(namespacePivotKubeConfig); err != nil {
				fmt.Printf("[-] Error during namespace pivot analysis: %v\n", err)
			}
		},
	}
)

func init() {
	NamespacePivotCmd.Flags().StringVar(&namespacePivotKubeConfig, "kubeconfig", "", "Path to the kubeconfig file")
}

func extractServiceAccountTokens(clientset *k8s.Clientset, namespace string) {
	secrets, err := clientset.CoreV1().Secrets(namespace).List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		fmt.Printf("[-] Error listing secrets in %s: %v\n", namespace, err)
		return
	}

	for _, secret := range secrets.Items {
		if secret.Type == v1.SecretTypeServiceAccountToken {
			sa := secret.Annotations["kubernetes.io/service-account.name"]
			token := base64.StdEncoding.EncodeToString(secret.Data["token"])
			fmt.Printf("[+] Found ServiceAccount token in namespace %s (SA: %s): %s...\n", namespace, sa, token[:50])
		}
	}
}

func listRBACBindings(clientset *k8s.Clientset, namespace string) {
	roleBindings, err := clientset.RbacV1().RoleBindings(namespace).List(context.TODO(), metav1.ListOptions{})
	if err == nil {
		for _, rb := range roleBindings.Items {
			fmt.Printf("[*] RoleBinding in %s: %s -> %s\n", namespace, rb.Subjects, rb.RoleRef.Name)
		}
	}

	clusterRoleBindings, err := clientset.RbacV1().ClusterRoleBindings().List(context.TODO(), metav1.ListOptions{})
	if err == nil {
		for _, crb := range clusterRoleBindings.Items {
			for _, subject := range crb.Subjects {
				if subject.Namespace == namespace {
					fmt.Printf("[*] ClusterRoleBinding affecting %s: %s -> %s\n", namespace, subject.Name, crb.RoleRef.Name)
				}
			}
		}
	}
}

func checkServiceAccountAccess(clientset *k8s.Clientset, namespace string) {
	sas, err := clientset.CoreV1().ServiceAccounts(namespace).List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		fmt.Printf("[-] Could not list service accounts in %s: %v\n", namespace, err)
		return
	}

	for _, sa := range sas.Items {
		fmt.Printf("[+] Found SA in %s: %s\n", namespace, sa.Name)
	}
}

func NamespacePivot(kubeconfig string) error {
	var config *rest.Config
	var err error

	if kubeconfig == "" {
		config, err = rest.InClusterConfig()
	} else {
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
	}
	if err != nil {
		return fmt.Errorf("unable to load kube config: %v", err)
	}

	clientset, err := k8s.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("failed to create client: %v", err)
	}

	namespaces, err := clientset.CoreV1().Namespaces().List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("could not list namespaces: %v", err)
	}

	fmt.Println("[*] Enumerating namespaces and service accounts for pivot opportunities...")

	for _, ns := range namespaces.Items {
		fmt.Printf("\n=== Namespace: %s ===\n", ns.Name)
		checkServiceAccountAccess(clientset, ns.Name)
		extractServiceAccountTokens(clientset, ns.Name)
		listRBACBindings(clientset, ns.Name)
	}

	return nil
}
