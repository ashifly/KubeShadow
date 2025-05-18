package modules

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/spf13/cobra"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8s "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

var (
	kubeConfigPath string

	// DNSCachePoisonCmd represents the DNS cache poisoning analysis command
	DNSCachePoisonCmd = &cobra.Command{
		Use:   "dns-poison",
		Short: "Test for DNS cache poisoning vulnerabilities",
		Long:  `Analyzes CoreDNS configuration and tests for potential DNS cache poisoning vectors in the cluster`,
		Run: func(cmd *cobra.Command, args []string) {
			if err := DNSCachePoison(kubeConfigPath); err != nil {
				fmt.Printf("[-] Error during DNS cache poisoning analysis: %v\n", err)
			}
		},
	}
)

func init() {
	DNSCachePoisonCmd.Flags().StringVar(&kubeConfigPath, "kubeconfig", "", "Path to the kubeconfig file")
}

func dnsLookup(name string) {
	fmt.Printf("[*] Resolving: %s\n", name)
	addrs, err := net.LookupHost(name)
	if err != nil {
		fmt.Printf("[-] DNS lookup failed: %v\n", err)
	} else {
		fmt.Printf("[+] DNS resolution for %s: %v\n", name, addrs)
	}
}

func detectSuspiciousCoreDNSConfig(configMap v1.ConfigMap) {
	data := configMap.Data["Corefile"]
	if strings.Contains(data, "rewrite") || strings.Contains(data, "template") {
		fmt.Println("[!] CoreDNS config contains rewrite/template logic, may support DNS spoofing.")
	}
	if strings.Contains(data, "fallthrough") {
		fmt.Println("[!] CoreDNS config has fallthrough, may allow wildcard shadowing of services.")
	}
}

func DNSCachePoison(kubeconfig string) error {
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

	// Step 1: Look for suspicious CoreDNS config
	fmt.Println("[*] Checking CoreDNS ConfigMap...")
	cm, err := clientset.CoreV1().ConfigMaps("kube-system").Get(context.TODO(), "coredns", metav1.GetOptions{})
	if err == nil {
		detectSuspiciousCoreDNSConfig(*cm)
	} else {
		fmt.Println("[-] Could not find CoreDNS configmap. Skipping analysis.")
	}

	// Step 2: Deploy a pod and inject fake DNS entries (simulated here by lookup)
	fmt.Println("[*] Testing DNS cache with known and fake lookups...")
	dnsLookup("kubernetes.default.svc.cluster.local")
	dnsLookup("internal.fake.svc.cluster.local")

	// Step 3: Try shadowing real services with spoofed names
	pods, err := clientset.CoreV1().Pods("default").List(context.TODO(), metav1.ListOptions{})
	if err == nil && len(pods.Items) > 0 {
		name := pods.Items[0].Name
		dnsName := fmt.Sprintf("%s.default.svc.cluster.local", name)
		fmt.Printf("[*] Attempting resolution of real pod DNS: %s\n", dnsName)
		dnsLookup(dnsName)
	}

	// Step 4: Attempt known poisoned targets
	suspicious := []string{
		"google.internal.svc.cluster.local",
		"aws.internal.svc.cluster.local",
		"metadata.google.internal",
	}
	for _, target := range suspicious {
		dnsLookup(target)
	}

	return nil
}
