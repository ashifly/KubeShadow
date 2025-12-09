package lab

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/spf13/cobra"
)

// ClusterConfig represents cluster configuration options
type ClusterConfig struct {
	NumNodes    int
	MinNodes    int
	MaxNodes    int
	MachineType string
	DiskSize    string
	DiskType    string
}

var LabCmd = &cobra.Command{
	Use:   "lab",
	Short: "Deploy KubeShadow lab environment for security testing",
	Long: `Deploy a complete KubeShadow lab environment with intentionally vulnerable configurations
for hands-on security testing practice. Supports cloud providers and local environments.

Cluster size options (optimized for minimal costs and disk usage):
- minimal: 1 node, 30GB disk (t3.small/e2-standard-2/Standard_B2s) - FASTEST, avoids quota issues
- small: 2 nodes, 50GB disk (t3.medium/e2-standard-2/Standard_B2s)  
- medium: 3 nodes, 100GB disk (t3.large/e2-standard-4/Standard_B4ms)

All providers use optimized configurations:
- AWS: t3 instances with GP3 disks for better performance
- GCP: Zonal clusters with standard disks to avoid SSD quota
- Azure: Standard SSD disks to avoid premium quota issues

Examples:
  kubeshadow lab --provider minikube
  kubeshadow lab --provider aws --cluster-size minimal --use-spot
  kubeshadow lab --provider gcp --cluster-size minimal --use-spot
  kubeshadow lab --provider azure --cluster-size minimal --use-spot`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Execute lab creation
		provider, err := cmd.Flags().GetString("provider")
		if err != nil {
			return fmt.Errorf("failed to get provider flag: %w", err)
		}

		region, err := cmd.Flags().GetString("region")
		if err != nil {
			return fmt.Errorf("failed to get region flag: %w", err)
		}

		// Set provider-specific defaults if region not provided
		if region == "" {
			switch provider {
			case "aws":
				region = "us-west-2"
			case "gcp":
				region = "us-west2"
			case "azure":
				region = "eastus"
			}
		}

		// Normalize GCP region format (convert us-west-2 to us-west2)
		if provider == "gcp" {
			region = normalizeGCPRegion(region)
		}

		clusterName, err := cmd.Flags().GetString("cluster-name")
		if err != nil {
			return fmt.Errorf("failed to get cluster-name flag: %w", err)
		}

		skipAuth, err := cmd.Flags().GetBool("skip-auth")
		if err != nil {
			return fmt.Errorf("failed to get skip-auth flag: %w", err)
		}

		clusterSize, err := cmd.Flags().GetString("cluster-size")
		if err != nil {
			return fmt.Errorf("failed to get cluster-size flag: %w", err)
		}

		useSpot, err := cmd.Flags().GetBool("use-spot")
		if err != nil {
			return fmt.Errorf("failed to get use-spot flag: %w", err)
		}

		fmt.Println("🎯 KubeShadow Lab Deployment")
		fmt.Println("================================")

		// Validate provider
		validProviders := []string{"aws", "gcp", "azure", "minikube", "kind", "local"}
		if !contains(validProviders, provider) {
			return fmt.Errorf("invalid provider: %s. Valid options: %s", provider, strings.Join(validProviders, ", "))
		}

		// Handle cloud providers
		if contains([]string{"aws", "gcp", "azure"}, provider) {
			if !skipAuth {
				fmt.Printf("🔐 Please authenticate with %s first:\n", strings.ToUpper(provider))
				if err := authenticateCloudProvider(provider); err != nil {
					return fmt.Errorf("authentication failed: %w", err)
				}
			}

			fmt.Printf("☁️  Deploying lab environment to %s...\n", strings.ToUpper(provider))
			fmt.Printf("📏 Cluster size: %s\n", clusterSize)
			if useSpot {
				fmt.Println("💰 Using spot instances for cost savings")
			}
			return deployCloudLab(provider, region, clusterName, clusterSize, useSpot)
		}

		// Handle local environments
		if contains([]string{"minikube", "kind", "local"}, provider) {
			fmt.Printf("🏠 Deploying lab environment to %s...\n", provider)
			return deployLocalLab(provider, clusterName)
		}

		return fmt.Errorf("unsupported provider: %s", provider)
	},
}

func init() {
	LabCmd.Flags().String("provider", "minikube", "Cloud provider or local environment (aws, gcp, azure, minikube, kind, local)")
	LabCmd.Flags().String("region", "", "Cloud region (for cloud providers). Defaults: aws=us-west-2, gcp=us-west2, azure=eastus")
	LabCmd.Flags().String("cluster-name", "kubeshadow-lab", "Name for the Kubernetes cluster")
	LabCmd.Flags().Bool("skip-auth", false, "Skip cloud authentication (use existing credentials)")
	LabCmd.Flags().String("cluster-size", "minimal", "Cluster size: minimal (1 node, 20GB), small (2 nodes, 50GB), medium (3 nodes, 100GB)")
	LabCmd.Flags().Bool("use-spot", false, "Use spot instances for cost savings (cloud providers only)")

	// Add cleanup subcommand
	LabCmd.AddCommand(LabCleanupCmd)
}

// authenticateCloudProvider handles cloud provider authentication
func authenticateCloudProvider(provider string) error {
	// Check if running in a headless environment (SSH, PuTTY, WSL, etc.)
	isHeadless := os.Getenv("SSH_CONNECTION") != "" || 
		os.Getenv("SSH_CLIENT") != "" || 
		os.Getenv("SSH_TTY") != "" ||
		os.Getenv("TERM") == "dumb" ||
		os.Getenv("DISPLAY") == ""

	switch provider {
	case "aws":
		fmt.Println("   Run: aws configure")
		fmt.Println("   Or: aws sso login")
		if isHeadless {
			fmt.Println("   Note: For headless environments, ensure AWS credentials are configured via:")
			fmt.Println("         - Environment variables (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)")
			fmt.Println("         - ~/.aws/credentials file")
			fmt.Println("         - IAM instance profile (if running on EC2)")
		}
		fmt.Print("   Press Enter when authenticated...")
		fmt.Scanln()
	case "gcp":
		if isHeadless {
			fmt.Println("   For headless environments (SSH/PuTTY/WSL), use:")
			fmt.Println("   Run: gcloud auth login --no-launch-browser")
			fmt.Println("        (Copy the URL to your local browser and paste the authorization code)")
			fmt.Println("   And: gcloud auth application-default login --no-launch-browser")
			fmt.Println("")
			fmt.Println("   Alternative: Use service account key file:")
			fmt.Println("   Run: export GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account-key.json")
			fmt.Println("   Or:  gcloud auth activate-service-account --key-file=/path/to/key.json")
		} else {
			fmt.Println("   Run: gcloud auth login")
			fmt.Println("   And: gcloud auth application-default login")
		}
		fmt.Print("   Press Enter when authenticated...")
		fmt.Scanln()
	case "azure":
		if isHeadless {
			fmt.Println("   For headless environments (SSH/PuTTY/WSL), use:")
			fmt.Println("   Run: az login --use-device-code")
			fmt.Println("        (Use the device code shown to authenticate via browser)")
			fmt.Println("")
			fmt.Println("   Alternative: Use service principal:")
			fmt.Println("   Run: az login --service-principal -u <app-id> -p <password> --tenant <tenant-id>")
		} else {
			fmt.Println("   Run: az login")
		}
		fmt.Print("   Press Enter when authenticated...")
		fmt.Scanln()
	}
	return nil
}

// deployCloudLab deploys lab to cloud providers
func deployCloudLab(provider, region, clusterName, clusterSize string, useSpot bool) error {
	fmt.Printf("🚀 Creating %s cluster: %s in region: %s\n", provider, clusterName, region)
	fmt.Printf("📏 Cluster size: %s\n", clusterSize)
	if useSpot {
		fmt.Println("💰 Using spot instances for cost savings")
	}

	switch provider {
	case "aws":
		return deployAWSLab(region, clusterName, clusterSize, useSpot)
	case "gcp":
		return deployGCPLab(region, clusterName, clusterSize, useSpot)
	case "azure":
		return deployAzureLab(region, clusterName, clusterSize, useSpot)
	}

	return fmt.Errorf("unsupported cloud provider: %s", provider)
}

// deployLocalLab deploys lab to local environments
func deployLocalLab(provider, clusterName string) error {
	fmt.Printf("🏠 Setting up %s environment: %s\n", provider, clusterName)

	switch provider {
	case "minikube":
		return deployMinikubeLab()
	case "kind":
		return deployKindLab(clusterName)
	case "local":
		return deployLocalK8sLab()
	}

	return fmt.Errorf("unsupported local provider: %s", provider)
}

// deployAWSLab creates EKS cluster and deploys lab
func deployAWSLab(region, clusterName, clusterSize string, useSpot bool) error {
	fmt.Println("📦 Creating EKS cluster...")

	// Get cluster configuration based on size
	config := getAWSClusterConfig(clusterSize, useSpot)
	fmt.Printf("💡 Using %s cluster configuration to reduce costs and disk usage...\n", clusterSize)
	fmt.Printf("📊 Nodes: %d, Instance: %s\n", config.NumNodes, config.MachineType)

	// Create EKS cluster with minimal configuration optimized for lab
	args := []string{
		"create", "cluster",
		"--name", clusterName,
		"--region", region,
		"--nodegroup-name", "workers",
		"--node-type", config.MachineType,
		"--nodes", fmt.Sprintf("%d", config.NumNodes),
		"--nodes-min", fmt.Sprintf("%d", config.MinNodes),
		"--nodes-max", fmt.Sprintf("%d", config.MaxNodes),
		"--managed",
		"--with-oidc",
		"--ssh-access",
		"--ssh-public-key", "kubeshadow-lab",
		"--full-ecr-access",
		"--node-volume-size", config.DiskSize,
		"--node-volume-type", config.DiskType,
		"--node-ami-family", "AmazonLinux2", // Use AL2 for better compatibility
	}

	// Add spot instance configuration if requested
	if useSpot {
		args = append(args, "--spot")
	}

	cmd := exec.Command("eksctl", args...)

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to create EKS cluster: %w", err)
	}

	// Update kubeconfig
	cmd = exec.Command("aws", "eks", "update-kubeconfig", "--region", region, "--name", clusterName)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to update kubeconfig: %w", err)
	}

	return deployLabManifests()
}

// deployGCPLab creates GKE cluster and deploys lab
func deployGCPLab(region, clusterName, clusterSize string, useSpot bool) error {
	fmt.Println("📦 Creating GKE cluster...")

	// Get cluster configuration based on size
	config := getGCPClusterConfig(clusterSize, useSpot)
	fmt.Printf("💡 Using %s cluster configuration to reduce costs and disk usage...\n", clusterSize)
	fmt.Printf("📊 Nodes: %d, Disk: %s, Machine: %s\n", config.NumNodes, config.DiskSize, config.MachineType)

	// Use zonal cluster for minimal configuration (fastest, avoids SSD quota)
	// GCP regions are formatted like "us-west2", zones are like "us-west2-b"
	zone := region + "-b" // Use zone b for the region (e.g., us-west2-b)

	// Create GKE cluster with minimal zonal configuration
	args := []string{
		"container", "clusters", "create", clusterName,
		"--zone", zone, // Use zone instead of region for minimal config
		"--num-nodes", fmt.Sprintf("%d", config.NumNodes),
		"--machine-type", config.MachineType,
		"--disk-size", config.DiskSize,
		"--disk-type", config.DiskType,
		"--no-enable-insecure-kubelet-readonly-port", // Security: disable insecure kubelet port
	}

	// Add spot instance configuration if requested
	if useSpot {
		args = append(args, "--preemptible")
	}

	cmd := exec.Command("gcloud", args...)

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to create GKE cluster: %w", err)
	}

	// Ensure gke-gcloud-auth-plugin is installed (required for modern GKE clusters)
	fmt.Println("🔌 Checking for gke-gcloud-auth-plugin...")
	if err := ensureGKEAuthPlugin(); err != nil {
		fmt.Printf("⚠️  Warning: Failed to install gke-gcloud-auth-plugin: %v\n", err)
		fmt.Println("   You may need to install it manually:")
		fmt.Println("   Run: gcloud components install gke-gcloud-auth-plugin")
		fmt.Println("   Or:  sudo apt-get install google-cloud-sdk-gke-gcloud-auth-plugin")
		return fmt.Errorf("gke-gcloud-auth-plugin is required but not installed. Please install it and try again")
	}

	// Get cluster credentials
	fmt.Println("🔑 Getting cluster credentials...")
	cmd = exec.Command("gcloud", "container", "clusters", "get-credentials", clusterName, "--zone", zone)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to get cluster credentials: %w", err)
	}

	return deployLabManifests()
}

// deployAzureLab creates AKS cluster and deploys lab
func deployAzureLab(region, clusterName, clusterSize string, useSpot bool) error {
	fmt.Println("📦 Creating AKS cluster...")

	// Get cluster configuration based on size
	config := getAzureClusterConfig(clusterSize, useSpot)
	fmt.Printf("💡 Using %s cluster configuration to reduce costs and disk usage...\n", clusterSize)
	fmt.Printf("📊 Nodes: %d, Instance: %s\n", config.NumNodes, config.MachineType)

	// Create resource group
	resourceGroup := clusterName + "-rg"
	cmd := exec.Command("az", "group", "create", "--name", resourceGroup, "--location", region)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to create resource group: %w", err)
	}

	// Create AKS cluster with minimal configuration optimized for lab
	args := []string{
		"aks", "create",
		"--resource-group", resourceGroup,
		"--name", clusterName,
		"--node-count", fmt.Sprintf("%d", config.NumNodes),
		"--node-vm-size", config.MachineType,
		"--node-osdisk-size", config.DiskSize,
		"--node-osdisk-type", config.DiskType,
		"--enable-addons", "monitoring",
		"--generate-ssh-keys",
		"--network-plugin", "kubenet", // Use kubenet for simplicity
		"--no-wait", // Don't wait for completion to speed up
	}

	// Add spot instance configuration if requested
	if useSpot {
		args = append(args, "--enable-ultra-ssd")
	}

	cmd = exec.Command("az", args...)

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to create AKS cluster: %w", err)
	}

	// Get cluster credentials
	cmd = exec.Command("az", "aks", "get-credentials", "--resource-group", resourceGroup, "--name", clusterName)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to get cluster credentials: %w", err)
	}

	return deployLabManifests()
}

// deployMinikubeLab sets up minikube and deploys lab
func deployMinikubeLab() error {
	fmt.Println("📦 Starting minikube...")

	// Start minikube
	cmd := exec.Command("minikube", "start", "--driver=docker", "--memory=4096", "--cpus=2")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to start minikube: %w", err)
	}

	// Enable addons
	addons := []string{"ingress", "metrics-server", "dashboard"}
	for _, addon := range addons {
		cmd = exec.Command("minikube", "addons", "enable", addon)
		if err := cmd.Run(); err != nil {
			fmt.Printf("⚠️  Warning: Failed to enable addon %s: %v\n", addon, err)
		}
	}

	return deployLabManifests()
}

// deployKindLab sets up kind and deploys lab
func deployKindLab(clusterName string) error {
	fmt.Println("📦 Creating kind cluster...")

	// Create kind cluster config
	kindConfig := fmt.Sprintf(`kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
name: %s
nodes:
- role: control-plane
  kubeadmConfigPatches:
  - |
    kind: InitConfiguration
    nodeRegistration:
      kubeletExtraArgs:
        node-labels: "ingress-ready=true"
  extraPortMappings:
  - containerPort: 80
    hostPort: 80
    protocol: TCP
  - containerPort: 443
    hostPort: 443
    protocol: TCP
- role: worker
- role: worker`, clusterName)

	configFile := "kind-config.yaml"
	if err := os.WriteFile(configFile, []byte(kindConfig), 0644); err != nil {
		return fmt.Errorf("failed to create kind config: %w", err)
	}
	defer os.Remove(configFile)

	// Create kind cluster
	cmd := exec.Command("kind", "create", "cluster", "--config", configFile)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to create kind cluster: %w", err)
	}

	return deployLabManifests()
}

// deployLocalK8sLab deploys to existing local cluster
func deployLocalK8sLab() error {
	fmt.Println("📦 Deploying to existing local cluster...")

	// Check if kubectl can connect
	cmd := exec.Command("kubectl", "cluster-info")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("cannot connect to local cluster: %w", err)
	}

	return deployLabManifests()
}

// deployLabManifests deploys all lab YAML files
func deployLabManifests() error {
	fmt.Println("🚀 Deploying lab manifests...")

	labDir := "modules/lab/manifests"
	yamlFiles := []string{
		"01-namespace.yaml",
		"02-rbac.yaml",
		"03-pods.yaml",
		"04-services.yaml",
		"05-secrets.yaml",
		"06-configmaps.yaml",
		"07-network-policies.yaml",
		"08-persistent-volumes.yaml",
		"09-ephemeral-containers.yaml",
		"10-secure-ephemeral.yaml",
		"11-ephemeral-attack-scenarios.yaml",
		"12-advanced-vulnerabilities.yaml",
		"13-chroot-escape.yaml",
		"14-secure-chroot.yaml",
		"15-highly-vulnerable.yaml",
		"16-owasp-comprehensive.yaml",
		"17-ssrf-vulnerability.yaml",
		"18-container-escape.yaml",
		"19-supply-chain-attack.yaml",
		"20-crypto-miner.yaml",
		"21-dns-poisoning.yaml",
		"22-cve-2025-1974-ingress-nginx-rce.yaml",
		"23-cve-2025-5187-node-ownerreference.yaml",
		"24-tls-bootstrap-azure.yaml",
	}

	for _, file := range yamlFiles {
		filePath := filepath.Join(labDir, file)
		fmt.Printf("   📄 Applying %s...\n", file)

		cmd := exec.Command("kubectl", "apply", "-f", filePath)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		if err := cmd.Run(); err != nil {
			fmt.Printf("⚠️  Warning: Failed to apply %s: %v\n", file, err)
		}
	}

	// Wait for pods to be ready
	fmt.Println("⏳ Waiting for pods to be ready...")
	cmd := exec.Command("kubectl", "wait", "--for=condition=Ready", "pod", "--all", "-n", "kubeshadow-lab", "--timeout=120s")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		fmt.Printf("⚠️  Warning: Some pods may not be ready: %v\n", err)
	}

	// Display lab status
	fmt.Println("\n🎉 Lab deployment complete!")
	fmt.Println("\n📊 Lab Status:")

	cmd = exec.Command("kubectl", "get", "pods", "-n", "kubeshadow-lab")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Run()

	fmt.Println("\n🌐 Services:")
	cmd = exec.Command("kubectl", "get", "services", "-n", "kubeshadow-lab")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Run()

	fmt.Println("\n🔑 Secrets:")
	cmd = exec.Command("kubectl", "get", "secrets", "-n", "kubeshadow-lab")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Run()

	fmt.Println("\n🎓 Ready for KubeShadow exercises!")
	fmt.Println("\nNext steps:")
	fmt.Println("1. Start KubeShadow dashboard: ./kubeshadow dashboard")
	fmt.Println("2. Run reconnaissance: ./kubeshadow recon --dashboard")
	fmt.Println("3. Explore the lab environment and identify security issues")
	fmt.Println("\nHappy learning! 🚀")

	return nil
}

// contains checks if a string is in a slice
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// getClusterConfig returns cluster configuration based on size and spot preferences
func getClusterConfig(clusterSize string, _ bool) ClusterConfig {
	switch clusterSize {
	case "minimal":
		return ClusterConfig{
			NumNodes:    1,
			MinNodes:    1,
			MaxNodes:    2,
			MachineType: "t3.micro", // Default to AWS, will be overridden per provider
			DiskSize:    "20GB",
			DiskType:    "gp2",
		}
	case "small":
		return ClusterConfig{
			NumNodes:    2,
			MinNodes:    1,
			MaxNodes:    3,
			MachineType: "t3.small",
			DiskSize:    "50GB",
			DiskType:    "gp2",
		}
	case "medium":
		return ClusterConfig{
			NumNodes:    3,
			MinNodes:    2,
			MaxNodes:    5,
			MachineType: "t3.medium",
			DiskSize:    "100GB",
			DiskType:    "gp2",
		}
	default:
		// Default to minimal for unknown sizes
		return ClusterConfig{
			NumNodes:    1,
			MinNodes:    1,
			MaxNodes:    2,
			MachineType: "t3.micro",
			DiskSize:    "20GB",
			DiskType:    "gp2",
		}
	}
}

// getGCPClusterConfig returns GCP-specific cluster configuration
func getGCPClusterConfig(clusterSize string, useSpot bool) ClusterConfig {
	config := getClusterConfig(clusterSize, useSpot)

	// Override with GCP-specific values optimized for minimal zonal clusters
	switch clusterSize {
	case "minimal":
		config.MachineType = "e2-standard-2" // 2 vCPU, 8 GB RAM (better than e2-micro for lab)
		config.DiskType = "pd-standard"      // Standard disk to avoid SSD quota issues
		config.DiskSize = "30"               // 30GB disk (minimal but sufficient)
	case "small":
		config.MachineType = "e2-standard-2"
		config.DiskType = "pd-standard"
		config.DiskSize = "50"
	case "medium":
		config.MachineType = "e2-standard-4" // 4 vCPU, 16 GB RAM
		config.DiskType = "pd-standard"
		config.DiskSize = "100"
	}

	return config
}

// normalizeGCPRegion converts AWS-style region format to GCP format
// e.g., "us-west-2" -> "us-west2", "us-east-1" -> "us-east1"
func normalizeGCPRegion(region string) string {
	// GCP regions don't have a dash before the number
	// Pattern: convert "us-west-2" to "us-west2"
	// This handles common cases like us-west-2, us-east-1, etc.
	if strings.Contains(region, "-") {
		parts := strings.Split(region, "-")
		if len(parts) >= 3 {
			// Last part is the number, combine everything before it
			// e.g., ["us", "west", "2"] -> "us-west2"
			prefix := strings.Join(parts[:len(parts)-1], "-")
			suffix := parts[len(parts)-1]
			region = prefix + suffix
		}
	}
	return region
}

// ensureGKEAuthPlugin checks if gke-gcloud-auth-plugin is installed and installs it if not
func ensureGKEAuthPlugin() error {
	// Check if plugin is already installed and accessible in PATH
	cmd := exec.Command("gke-gcloud-auth-plugin", "--version")
	if err := cmd.Run(); err == nil {
		// Plugin is already installed
		fmt.Println("   ✓ gke-gcloud-auth-plugin is already installed")
		return nil
	}

	// Plugin not found, try to install
	fmt.Println("   Installing gke-gcloud-auth-plugin (required for GKE authentication)...")
	
	// Try to install via gcloud components first (works on all platforms)
	installCmd := exec.Command("gcloud", "components", "install", "gke-gcloud-auth-plugin", "--quiet")
	installCmd.Stdout = os.Stdout
	installCmd.Stderr = os.Stderr
	
	if err := installCmd.Run(); err == nil {
		// Installation succeeded, verify
		verifyCmd := exec.Command("gke-gcloud-auth-plugin", "--version")
		if verifyErr := verifyCmd.Run(); verifyErr == nil {
			fmt.Println("   ✓ gke-gcloud-auth-plugin installed successfully")
			return nil
		}
		// Installation reported success but plugin still not found
		fmt.Println("   ⚠️  Installation completed but plugin not found in PATH")
	}

	// If gcloud components install fails, try platform-specific methods
	if runtime.GOOS == "linux" {
		fmt.Println("   Trying alternative installation method (apt-get)...")
		// Check if we're on a Debian-based system
		aptCmd := exec.Command("which", "apt-get")
		if aptCheckErr := aptCmd.Run(); aptCheckErr == nil {
			aptCmd = exec.Command("sudo", "apt-get", "update", "-qq")
			aptCmd.Stderr = os.Stderr
			aptCmd.Run() // Ignore errors, just try
			
			aptCmd = exec.Command("sudo", "apt-get", "install", "-y", "google-cloud-sdk-gke-gcloud-auth-plugin")
			aptCmd.Stdout = os.Stdout
			aptCmd.Stderr = os.Stderr
			if aptErr := aptCmd.Run(); aptErr == nil {
				verifyCmd := exec.Command("gke-gcloud-auth-plugin", "--version")
				if verifyErr := verifyCmd.Run(); verifyErr == nil {
					fmt.Println("   ✓ gke-gcloud-auth-plugin installed successfully via apt-get")
					return nil
				}
			}
		}
	}

	// All installation methods failed
	return fmt.Errorf("gke-gcloud-auth-plugin is required but could not be installed automatically. Please install it manually:\n" +
		"   - Run: gcloud components install gke-gcloud-auth-plugin\n" +
		"   - Or (Linux): sudo apt-get install google-cloud-sdk-gke-gcloud-auth-plugin\n" +
		"   - Or (macOS): brew install gke-gcloud-auth-plugin\n" +
		"   Then run the lab creation command again")
}

// getAWSClusterConfig returns AWS-specific cluster configuration
func getAWSClusterConfig(clusterSize string, useSpot bool) ClusterConfig {
	config := getClusterConfig(clusterSize, useSpot)

	// Override with AWS-specific values optimized for minimal lab clusters
	switch clusterSize {
	case "minimal":
		config.MachineType = "t3.small" // 2 vCPU, 2 GB RAM (better than t3.micro for lab)
		config.DiskType = "gp3"         // GP3 for better performance than gp2
		config.DiskSize = "30"          // 30GB disk (minimal but sufficient)
	case "small":
		config.MachineType = "t3.medium" // 2 vCPU, 4 GB RAM
		config.DiskType = "gp3"
		config.DiskSize = "50"
	case "medium":
		config.MachineType = "t3.large" // 2 vCPU, 8 GB RAM
		config.DiskType = "gp3"
		config.DiskSize = "100"
	}

	return config
}

// getAzureClusterConfig returns Azure-specific cluster configuration
func getAzureClusterConfig(clusterSize string, useSpot bool) ClusterConfig {
	config := getClusterConfig(clusterSize, useSpot)

	// Override with Azure-specific values optimized for minimal lab clusters
	switch clusterSize {
	case "minimal":
		config.MachineType = "Standard_B2s" // 2 vCPU, 4 GB RAM (better than B1s for lab)
		config.DiskType = "StandardSSD_LRS" // Standard SSD to avoid premium quota issues
		config.DiskSize = "30"              // 30GB disk (minimal but sufficient)
	case "small":
		config.MachineType = "Standard_B2s" // 2 vCPU, 4 GB RAM
		config.DiskType = "StandardSSD_LRS"
		config.DiskSize = "50"
	case "medium":
		config.MachineType = "Standard_B4ms" // 4 vCPU, 16 GB RAM
		config.DiskType = "StandardSSD_LRS"
		config.DiskSize = "100"
	}

	return config
}
