package recon

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

// BasicK8sRecon performs basic Kubernetes API reconnaissance.
// This is a simpler version of K8sRecon in k8s.go
func BasicK8sRecon(ctx context.Context, kubeconfig string, stealth bool) error {
	// Expand ~ in kubeconfig path if needed
	if kubeconfig[:2] == "~/" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("cannot find user home: %v", err)
		}
		kubeconfig = filepath.Join(homeDir, kubeconfig[2:])
	}

	// Load the kubeconfig file
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return fmt.Errorf("failed to load kubeconfig: %v", err)
	}

	// Create a Kubernetes client
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("failed to create k8s client: %v", err)
	}

	fmt.Println("[BasicK8sRecon] Connected to Kubernetes API")

	if stealth {
		fmt.Println("[BasicK8sRecon] Stealth mode enabled — limiting API calls")
		// Minimal action: get server version only
		versionInfo, err := clientset.Discovery().ServerVersion()
		if err != nil {
			return fmt.Errorf("failed to get server version: %v", err)
		}
		fmt.Printf("[BasicK8sRecon] Kubernetes version: %s\n", versionInfo.String())
	} else {
		// Full recon: list namespaces, pods, service accounts
		namespaces, err := clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
		if err != nil {
			return fmt.Errorf("failed to list namespaces: %v", err)
		}
		for _, ns := range namespaces.Items {
			fmt.Printf("[BasicK8sRecon] Found namespace: %s\n", ns.Name)

			pods, err := clientset.CoreV1().Pods(ns.Name).List(ctx, metav1.ListOptions{})
			if err == nil {
				fmt.Printf("  [*] %d pods found\n", len(pods.Items))
			}

			sas, err := clientset.CoreV1().ServiceAccounts(ns.Name).List(ctx, metav1.ListOptions{})
			if err == nil {
				fmt.Printf("  [*] %d service accounts found\n", len(sas.Items))
			}
		}
	}

	return nil
}

// CloudRecon performs cloud metadata enumeration
func CloudRecon(ctx context.Context, stealth bool) error {
	// Cloud metadata URL (works for AWS, GCP, Azure with minor changes)
	metadataURL := "http://169.254.169.254/latest/meta-data/"

	req, err := http.NewRequestWithContext(ctx, "GET", metadataURL, nil)
	if err != nil {
		fmt.Println("[CloudRecon] Metadata endpoint unreachable — not in cloud or blocked")
		return nil
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("[CloudRecon] Metadata endpoint unreachable — not in cloud or blocked")
		return nil
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)

	if stealth {
		fmt.Println("[CloudRecon] Stealth mode: only checked metadata availability")
	} else {
		fmt.Printf("[CloudRecon] Response from metadata service:\n%s\n", string(body))
	}

	return nil
}
