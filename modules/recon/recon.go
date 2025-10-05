package recon

import (
	"context"
	"fmt"
	"strings"

	"kubeshadow/pkg/recon"

	"github.com/spf13/cobra"
)

var ReconCmd = &cobra.Command{
	Use:   "recon",
	Short: "Perform comprehensive cluster, cloud, and system reconnaissance",
	RunE: func(cmd *cobra.Command, args []string) error {
		kubeconfig, err := cmd.Flags().GetString("kubeconfig")
		if err != nil {
			return fmt.Errorf("failed to get kubeconfig flag: %w", err)
		}
		stealth, err := cmd.Flags().GetBool("stealth")
		if err != nil {
			return fmt.Errorf("failed to get stealth flag: %w", err)
		}
		cloudOnly, err := cmd.Flags().GetBool("cloud-only")
		if err != nil {
			return fmt.Errorf("failed to get cloud-only flag: %w", err)
		}
		k8sOnly, err := cmd.Flags().GetBool("k8s-only")
		if err != nil {
			return fmt.Errorf("failed to get k8s-only flag: %w", err)
		}
		showRBAC, err := cmd.Flags().GetBool("show-rbac")
		if err != nil {
			return fmt.Errorf("failed to get show-rbac flag: %w", err)
		}
		systemOnly, err := cmd.Flags().GetBool("system-only")
		if err != nil {
			return fmt.Errorf("failed to get system-only flag: %w", err)
		}
		networkOnly, err := cmd.Flags().GetBool("network-only")
		if err != nil {
			return fmt.Errorf("failed to get network-only flag: %w", err)
		}
		containerOnly, err := cmd.Flags().GetBool("container-only")
		if err != nil {
			return fmt.Errorf("failed to get container-only flag: %w", err)
		}
		volumeOnly, err := cmd.Flags().GetBool("volume-only")
		if err != nil {
			return fmt.Errorf("failed to get volume-only flag: %w", err)
		}
		processOnly, err := cmd.Flags().GetBool("process-only")
		if err != nil {
			return fmt.Errorf("failed to get process-only flag: %w", err)
		}
		kubernetesOnly, err := cmd.Flags().GetBool("kubernetes-only")
		if err != nil {
			return fmt.Errorf("failed to get kubernetes-only flag: %w", err)
		}

		// Validate flags - only one "only" flag can be set
		onlyFlags := []bool{cloudOnly, k8sOnly, systemOnly, networkOnly, containerOnly, volumeOnly, processOnly, kubernetesOnly}
		onlyCount := 0
		for _, flag := range onlyFlags {
			if flag {
				onlyCount++
			}
		}
		if onlyCount > 1 {
			return fmt.Errorf("cannot specify multiple 'only' flags simultaneously")
		}

		ctx := context.Background()
		var reconErrors []error

		// Kubernetes API Reconnaissance
		if !cloudOnly && !systemOnly && !networkOnly && !containerOnly && !volumeOnly && !processOnly && !kubernetesOnly {
			fmt.Println("🔍 Starting Kubernetes API Recon...")
			if err := recon.K8sRecon(ctx, kubeconfig, stealth, showRBAC); err != nil {
				reconErrors = append(reconErrors, fmt.Errorf("kubernetes API recon failed: %w", err))
			}
		}

		// Pod Vulnerability Scanning
		if !cloudOnly && !systemOnly && !networkOnly && !containerOnly && !volumeOnly && !processOnly {
			fmt.Println("🚨 Starting Pod Vulnerability Scan...")
			if vulnerabilities, err := recon.PodVulnerabilityScan(ctx, kubeconfig); err != nil {
				reconErrors = append(reconErrors, fmt.Errorf("pod vulnerability scan failed: %w", err))
			} else {
				recon.PrintVulnerabilities(vulnerabilities)
			}
		}

		// Cloud Metadata Reconnaissance
		if !k8sOnly && !systemOnly && !networkOnly && !containerOnly && !volumeOnly && !processOnly && !kubernetesOnly {
			fmt.Println("☁️  Starting Cloud Metadata Recon...")
			if err := recon.CloudRecon(ctx, stealth); err != nil {
				reconErrors = append(reconErrors, fmt.Errorf("cloud recon failed: %w", err))
			}

			// Enhanced cloud reconnaissance
			if !stealth {
				fmt.Println("☁️  Starting Enhanced Cloud Recon...")
				if err := recon.CloudMetadataRecon(ctx, stealth); err != nil {
					reconErrors = append(reconErrors, fmt.Errorf("enhanced cloud recon failed: %w", err))
				}
			}
		}

		// Kubernetes In-Cluster Reconnaissance
		if !cloudOnly && !k8sOnly && !systemOnly && !networkOnly && !containerOnly && !volumeOnly && !processOnly {
			fmt.Println("🏗️  Starting Kubernetes In-Cluster Recon...")
			if k8sInfo, err := recon.GetKubernetesInfo(ctx); err != nil {
				if strings.Contains(err.Error(), "not running in a Kubernetes cluster") {
					fmt.Println("   ℹ️  Not running in Kubernetes cluster (running from outside)")
				} else {
					reconErrors = append(reconErrors, fmt.Errorf("kubernetes in-cluster recon failed: %w", err))
				}
			} else {
				fmt.Printf("   ✅ Running in Kubernetes cluster\n")
				if !stealth {
					fmt.Printf("   📋 Cluster: %s\n", k8sInfo.ClusterName)
					fmt.Printf("   📋 Namespace: %s\n", k8sInfo.Namespace)
					fmt.Printf("   📋 Pod: %s\n", k8sInfo.PodName)
					fmt.Printf("   📋 Node: %s\n", k8sInfo.NodeName)
					fmt.Printf("   📋 Service Account: %s\n", k8sInfo.ServiceAccount)
					fmt.Printf("   📋 Version: %s\n", k8sInfo.Version)
				}
			}
		}

		// System Reconnaissance
		if !cloudOnly && !k8sOnly && !networkOnly && !containerOnly && !volumeOnly && !processOnly && !kubernetesOnly {
			fmt.Println("💻 Starting System Recon...")
			if systemInfo, err := recon.GetSystemInfo(ctx); err != nil {
				reconErrors = append(reconErrors, fmt.Errorf("system recon failed: %w", err))
			} else {
				fmt.Printf("   ✅ Hostname: %s\n", systemInfo.Hostname)
				fmt.Printf("   ✅ OS: %s %s\n", systemInfo.OSInfo.Name, systemInfo.OSInfo.Version)
				fmt.Printf("   ✅ Architecture: %s\n", systemInfo.Architecture)
				fmt.Printf("   ✅ Kernel: %s\n", systemInfo.KernelVersion)
				if !stealth {
					fmt.Printf("   📋 CPU: %s (%d cores)\n", systemInfo.CPUInfo.Model, systemInfo.CPUInfo.Cores)
					fmt.Printf("   📋 Memory: %d MB total, %d MB free\n",
						systemInfo.MemoryInfo.Total/1024/1024,
						systemInfo.MemoryInfo.Free/1024/1024)
					fmt.Printf("   📋 Uptime: %v\n", systemInfo.Uptime)
				}
			}
		}

		// Network Reconnaissance
		if !cloudOnly && !k8sOnly && !systemOnly && !containerOnly && !volumeOnly && !processOnly && !kubernetesOnly {
			fmt.Println("🌐 Starting Network Recon...")
			if networkInfo, err := recon.GetNetworkInfo(ctx); err != nil {
				if strings.Contains(err.Error(), "failed to read /proc/net/tcp") ||
					strings.Contains(err.Error(), "Unable to get open ports") {
					fmt.Println("   ℹ️  Network recon limited on this platform")
				} else {
					reconErrors = append(reconErrors, fmt.Errorf("network recon failed: %w", err))
				}
			} else {
				fmt.Printf("   ✅ Hostname: %s\n", networkInfo.Hostname)
				fmt.Printf("   ✅ DNS Servers: %v\n", networkInfo.DNSServers)
				if !stealth {
					fmt.Printf("   📋 IP Addresses: %d found\n", len(networkInfo.IPAddresses))
					fmt.Printf("   📋 Network Interfaces: %d found\n", len(networkInfo.Interfaces))
					fmt.Printf("   📋 Open Ports: %d found\n", len(networkInfo.OpenPorts))
					fmt.Printf("   📋 Active Connections: %d found\n", len(networkInfo.Connections))
				}
			}
		}

		// Container Reconnaissance
		if !cloudOnly && !k8sOnly && !systemOnly && !networkOnly && !volumeOnly && !processOnly && !kubernetesOnly {
			fmt.Println("📦 Starting Container Recon...")
			if containers, err := recon.GetContainerInfo(ctx); err != nil {
				if strings.Contains(err.Error(), "no containers found") {
					fmt.Println("   ℹ️  No containers found (not running in container environment)")
				} else {
					reconErrors = append(reconErrors, fmt.Errorf("container recon failed: %w", err))
				}
			} else {
				fmt.Printf("   ✅ Found %d containers\n", len(containers))
				if !stealth {
					for _, container := range containers {
						fmt.Printf("   📋 %s (%s) - %s\n", container.Name, container.Image, container.Status)
					}
				}
			}
		}

		// Volume Reconnaissance
		if !cloudOnly && !k8sOnly && !systemOnly && !networkOnly && !containerOnly && !processOnly && !kubernetesOnly {
			fmt.Println("💾 Starting Volume Recon...")
			if volumes, err := recon.GetVolumeInfo(ctx); err != nil {
				if strings.Contains(err.Error(), "no volumes found") {
					fmt.Println("   ℹ️  No volumes found (not running in container environment)")
				} else {
					reconErrors = append(reconErrors, fmt.Errorf("volume recon failed: %w", err))
				}
			} else {
				fmt.Printf("   ✅ Found %d volumes\n", len(volumes))
				if !stealth {
					for _, volume := range volumes {
						fmt.Printf("   📋 %s (%s) - %s\n", volume.Name, volume.Driver, volume.MountPoint)
					}
				}
			}
		}

		// Process Reconnaissance
		if !cloudOnly && !k8sOnly && !systemOnly && !networkOnly && !containerOnly && !volumeOnly && !kubernetesOnly {
			fmt.Println("⚙️  Starting Process Recon...")
			if processes, err := recon.GetProcessInfo(ctx); err != nil {
				if strings.Contains(err.Error(), "failed to read /proc directory") ||
					strings.Contains(err.Error(), "Unable to get process information") {
					fmt.Println("   ℹ️  Process recon limited on this platform")
				} else {
					reconErrors = append(reconErrors, fmt.Errorf("process recon failed: %w", err))
				}
			} else {
				fmt.Printf("   ✅ Found %d processes\n", len(processes))
				if !stealth {
					// Show only first 10 processes in non-stealth mode
					for i, process := range processes {
						if i >= 10 {
							fmt.Printf("   📋 ... and %d more processes\n", len(processes)-10)
							break
						}
						fmt.Printf("   📋 PID %d: %s (%s)\n", process.PID, process.Name, process.User)
					}
				}
			}
		}

		if len(reconErrors) > 0 {
			return fmt.Errorf("recon completed with errors: %v", reconErrors)
		}
		return nil
	},
}

func init() {
	ReconCmd.Flags().String("kubeconfig", "~/.kube/config", "Path to the kubeconfig file")
	ReconCmd.Flags().Bool("stealth", true, "Enable stealth mode (minimal API calls)")
	ReconCmd.Flags().Bool("cloud-only", false, "Perform only cloud metadata recon")
	ReconCmd.Flags().Bool("k8s-only", false, "Perform only Kubernetes API recon")
	ReconCmd.Flags().Bool("show-rbac", false, "Show detailed RBAC analysis (RoleBindings and ClusterRoleBindings)")
	ReconCmd.Flags().Bool("system-only", false, "Perform only system reconnaissance")
	ReconCmd.Flags().Bool("network-only", false, "Perform only network reconnaissance")
	ReconCmd.Flags().Bool("container-only", false, "Perform only container reconnaissance")
	ReconCmd.Flags().Bool("volume-only", false, "Perform only volume reconnaissance")
	ReconCmd.Flags().Bool("process-only", false, "Perform only process reconnaissance")
	ReconCmd.Flags().Bool("kubernetes-only", false, "Perform only Kubernetes in-cluster reconnaissance")
}
