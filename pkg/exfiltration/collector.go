package exfiltration

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"kubeshadow/pkg/recon"

	"gopkg.in/yaml.v3"
)

// ReconData represents all collected reconnaissance data
type ReconData struct {
	Timestamp   time.Time              `json:"timestamp" yaml:"timestamp"`
	System      *recon.SystemInfo      `json:"system,omitempty" yaml:"system,omitempty"`
	Network     *recon.NetworkInfo     `json:"network,omitempty" yaml:"network,omitempty"`
	Containers  []recon.ContainerInfo  `json:"containers,omitempty" yaml:"containers,omitempty"`
	Volumes     []recon.VolumeInfo     `json:"volumes,omitempty" yaml:"volumes,omitempty"`
	Processes   []recon.ProcessInfo    `json:"processes,omitempty" yaml:"processes,omitempty"`
	Kubernetes  *recon.KubernetesInfo  `json:"kubernetes,omitempty" yaml:"kubernetes,omitempty"`
	Cloud       map[string]interface{} `json:"cloud,omitempty" yaml:"cloud,omitempty"`
	Environment []string               `json:"environment,omitempty" yaml:"environment,omitempty"`
}

// CollectReconData collects all available reconnaissance data and formats it
func CollectReconData(format string) ([]byte, error) {
	fmt.Println("🔍 Gathering system information...")

	ctx := context.Background()
	reconData := ReconData{
		Timestamp: time.Now(),
		Cloud:     make(map[string]interface{}),
	}

	// Collect system information
	if systemInfo, err := recon.GetSystemInfo(ctx); err == nil {
		reconData.System = &systemInfo
		fmt.Println("   ✅ System information collected")
	} else {
		fmt.Printf("   ⚠️  System information collection failed: %v\n", err)
	}

	// Collect network information
	if networkInfo, err := recon.GetNetworkInfo(ctx); err == nil {
		reconData.Network = networkInfo
		fmt.Println("   ✅ Network information collected")
	} else {
		fmt.Printf("   ⚠️  Network information collection failed: %v\n", err)
	}

	// Collect container information
	if containers, err := recon.GetContainerInfo(ctx); err == nil {
		// Convert from []*recon.ContainerInfo to []recon.ContainerInfo
		var containerList []recon.ContainerInfo
		for _, container := range containers {
			if container != nil {
				containerList = append(containerList, *container)
			}
		}
		reconData.Containers = containerList
		fmt.Printf("   ✅ Container information collected (%d containers)\n", len(containerList))
	} else {
		fmt.Printf("   ⚠️  Container information collection failed: %v\n", err)
	}

	// Collect volume information
	if volumes, err := recon.GetVolumeInfo(ctx); err == nil {
		reconData.Volumes = volumes
		fmt.Printf("   ✅ Volume information collected (%d volumes)\n", len(volumes))
	} else {
		fmt.Printf("   ⚠️  Volume information collection failed: %v\n", err)
	}

	// Collect process information
	if processes, err := recon.GetProcessInfo(ctx); err == nil {
		reconData.Processes = processes
		fmt.Printf("   ✅ Process information collected (%d processes)\n", len(processes))
	} else {
		fmt.Printf("   ⚠️  Process information collection failed: %v\n", err)
	}

	// Collect Kubernetes information
	if k8sInfo, err := recon.GetKubernetesInfo(ctx); err == nil {
		reconData.Kubernetes = k8sInfo
		fmt.Println("   ✅ Kubernetes information collected")
	} else {
		fmt.Printf("   ⚠️  Kubernetes information collection failed: %v\n", err)
	}

	// Collect cloud metadata
	if err := collectCloudMetadata(ctx, &reconData); err != nil {
		fmt.Printf("   ⚠️  Cloud metadata collection failed: %v\n", err)
	} else {
		fmt.Println("   ✅ Cloud metadata collected")
	}

	// Collect environment variables
	reconData.Environment = collectEnvironmentVars()
	fmt.Printf("   ✅ Environment variables collected (%d vars)\n", len(reconData.Environment))

	// Format the data based on requested format
	switch strings.ToLower(format) {
	case "json":
		return json.MarshalIndent(reconData, "", "  ")
	case "yaml":
		return yaml.Marshal(reconData)
	case "csv":
		return convertToCSV(reconData)
	default:
		return nil, fmt.Errorf("unsupported format: %s (supported: json, yaml, csv)", format)
	}
}

// collectCloudMetadata attempts to collect cloud metadata from various providers
func collectCloudMetadata(ctx context.Context, reconData *ReconData) error {
	// Try AWS metadata
	if err := recon.CloudRecon(ctx, false); err == nil {
		reconData.Cloud["aws"] = "available"
	}

	// Try enhanced cloud metadata
	if err := recon.CloudMetadataRecon(ctx, false); err == nil {
		reconData.Cloud["metadata"] = "available"
	}

	return nil
}

// collectEnvironmentVars collects environment variables (filtered for security)
func collectEnvironmentVars() []string {
	var filteredEnv []string

	// List of environment variable prefixes to exclude for security
	excludePrefixes := []string{
		"PASSWORD", "SECRET", "KEY", "TOKEN", "CREDENTIAL",
		"AWS_SECRET", "AZURE_CLIENT_SECRET", "GCP_PRIVATE_KEY",
	}

	for _, env := range GetEnvironment() {
		shouldExclude := false
		envUpper := strings.ToUpper(env)

		for _, prefix := range excludePrefixes {
			if strings.Contains(envUpper, prefix) {
				shouldExclude = true
				break
			}
		}

		if !shouldExclude {
			filteredEnv = append(filteredEnv, env)
		}
	}

	return filteredEnv
}

// convertToCSV converts reconnaissance data to CSV format
func convertToCSV(data ReconData) ([]byte, error) {
	var output strings.Builder
	writer := csv.NewWriter(&output)

	// Write header
	header := []string{"Category", "Key", "Value", "Timestamp"}
	writer.Write(header)

	timestamp := data.Timestamp.Format(time.RFC3339)

	// System information
	if data.System != nil {
		writer.Write([]string{"System", "Hostname", data.System.Hostname, timestamp})
		writer.Write([]string{"System", "OS", fmt.Sprintf("%s %s", data.System.OSInfo.Name, data.System.OSInfo.Version), timestamp})
		writer.Write([]string{"System", "Architecture", data.System.Architecture, timestamp})
		writer.Write([]string{"System", "Kernel", data.System.KernelVersion, timestamp})
		writer.Write([]string{"System", "CPU", fmt.Sprintf("%s (%d cores)", data.System.CPUInfo.Model, data.System.CPUInfo.Cores), timestamp})
		writer.Write([]string{"System", "Memory", fmt.Sprintf("%d MB", data.System.MemoryInfo.Total/1024/1024), timestamp})
	}

	// Network information
	if data.Network != nil {
		writer.Write([]string{"Network", "Hostname", data.Network.Hostname, timestamp})
		writer.Write([]string{"Network", "DNS Servers", strings.Join(data.Network.DNSServers, ","), timestamp})
		writer.Write([]string{"Network", "IP Addresses", fmt.Sprintf("%d found", len(data.Network.IPAddresses)), timestamp})
		writer.Write([]string{"Network", "Open Ports", fmt.Sprintf("%d found", len(data.Network.OpenPorts)), timestamp})
	}

	// Container information
	for i, container := range data.Containers {
		writer.Write([]string{"Container", fmt.Sprintf("Container_%d_Name", i), container.Name, timestamp})
		writer.Write([]string{"Container", fmt.Sprintf("Container_%d_Image", i), container.Image, timestamp})
		writer.Write([]string{"Container", fmt.Sprintf("Container_%d_Status", i), container.Status, timestamp})
	}

	// Process information (limited to first 50 for CSV readability)
	processLimit := 50
	if len(data.Processes) < processLimit {
		processLimit = len(data.Processes)
	}
	for i := 0; i < processLimit; i++ {
		process := data.Processes[i]
		writer.Write([]string{"Process", fmt.Sprintf("Process_%d_PID", i), fmt.Sprintf("%d", process.PID), timestamp})
		writer.Write([]string{"Process", fmt.Sprintf("Process_%d_Name", i), process.Name, timestamp})
		writer.Write([]string{"Process", fmt.Sprintf("Process_%d_User", i), process.User, timestamp})
	}

	// Kubernetes information
	if data.Kubernetes != nil {
		writer.Write([]string{"Kubernetes", "Namespace", data.Kubernetes.Namespace, timestamp})
		writer.Write([]string{"Kubernetes", "Pod", data.Kubernetes.PodName, timestamp})
		writer.Write([]string{"Kubernetes", "Node", data.Kubernetes.NodeName, timestamp})
		writer.Write([]string{"Kubernetes", "ServiceAccount", data.Kubernetes.ServiceAccount, timestamp})
	}

	writer.Flush()
	return []byte(output.String()), writer.Error()
}
