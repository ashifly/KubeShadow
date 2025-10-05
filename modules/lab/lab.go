package lab

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"kubeshadow/pkg/dashboard"

	"github.com/spf13/cobra"
)

var LabCmd = &cobra.Command{
	Use:   "lab",
	Short: "Deploy KubeShadow lab environment for security testing",
	Long: `Deploy a complete KubeShadow lab environment with intentionally vulnerable configurations
for hands-on security testing practice. Supports cloud providers and local environments.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Create dashboard wrapper
		wrapper := dashboard.NewCommandWrapper(cmd, "lab", "lab", args)

		return wrapper.Execute(func() error {
			provider, err := cmd.Flags().GetString("provider")
			if err != nil {
				return fmt.Errorf("failed to get provider flag: %w", err)
			}

			region, err := cmd.Flags().GetString("region")
			if err != nil {
				return fmt.Errorf("failed to get region flag: %w", err)
			}

			clusterName, err := cmd.Flags().GetString("cluster-name")
			if err != nil {
				return fmt.Errorf("failed to get cluster-name flag: %w", err)
			}

			skipAuth, err := cmd.Flags().GetBool("skip-auth")
			if err != nil {
				return fmt.Errorf("failed to get skip-auth flag: %w", err)
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
				return deployCloudLab(provider, region, clusterName)
			}

			// Handle local environments
			if contains([]string{"minikube", "kind", "local"}, provider) {
				fmt.Printf("🏠 Deploying lab environment to %s...\n", provider)
				return deployLocalLab(provider, clusterName)
			}

			return fmt.Errorf("unsupported provider: %s", provider)
		})
	},
}

func init() {
	LabCmd.Flags().String("provider", "minikube", "Cloud provider or local environment (aws, gcp, azure, minikube, kind, local)")
	LabCmd.Flags().String("region", "us-west-2", "Cloud region (for cloud providers)")
	LabCmd.Flags().String("cluster-name", "kubeshadow-lab", "Name for the Kubernetes cluster")
	LabCmd.Flags().Bool("skip-auth", false, "Skip cloud authentication (use existing credentials)")

	// Add cleanup subcommand
	LabCmd.AddCommand(LabCleanupCmd)
}

// authenticateCloudProvider handles cloud provider authentication
func authenticateCloudProvider(provider string) error {
	switch provider {
	case "aws":
		fmt.Println("   Run: aws configure")
		fmt.Println("   Or: aws sso login")
		fmt.Print("   Press Enter when authenticated...")
		fmt.Scanln()
	case "gcp":
		fmt.Println("   Run: gcloud auth login")
		fmt.Println("   And: gcloud auth application-default login")
		fmt.Print("   Press Enter when authenticated...")
		fmt.Scanln()
	case "azure":
		fmt.Println("   Run: az login")
		fmt.Print("   Press Enter when authenticated...")
		fmt.Scanln()
	}
	return nil
}

// deployCloudLab deploys lab to cloud providers
func deployCloudLab(provider, region, clusterName string) error {
	fmt.Printf("🚀 Creating %s cluster: %s in region: %s\n", provider, clusterName, region)

	switch provider {
	case "aws":
		return deployAWSLab(region, clusterName)
	case "gcp":
		return deployGCPLab(region, clusterName)
	case "azure":
		return deployAzureLab(region, clusterName)
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
func deployAWSLab(region, clusterName string) error {
	fmt.Println("📦 Creating EKS cluster...")

	// Create EKS cluster
	cmd := exec.Command("eksctl", "create", "cluster",
		"--name", clusterName,
		"--region", region,
		"--nodegroup-name", "workers",
		"--node-type", "t3.medium",
		"--nodes", "2",
		"--nodes-min", "1",
		"--nodes-max", "3",
		"--managed",
		"--with-oidc",
		"--ssh-access",
		"--ssh-public-key", "kubeshadow-lab",
		"--full-ecr-access")

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
func deployGCPLab(region, clusterName string) error {
	fmt.Println("📦 Creating GKE cluster...")

	// Create GKE cluster
	cmd := exec.Command("gcloud", "container", "clusters", "create", clusterName,
		"--region", region,
		"--num-nodes", "2",
		"--machine-type", "e2-medium",
		"--enable-autoscaling",
		"--min-nodes", "1",
		"--max-nodes", "3",
		"--enable-autorepair",
		"--enable-autoupgrade")

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to create GKE cluster: %w", err)
	}

	// Get cluster credentials
	cmd = exec.Command("gcloud", "container", "clusters", "get-credentials", clusterName, "--region", region)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to get cluster credentials: %w", err)
	}

	return deployLabManifests()
}

// deployAzureLab creates AKS cluster and deploys lab
func deployAzureLab(region, clusterName string) error {
	fmt.Println("📦 Creating AKS cluster...")

	// Create resource group
	resourceGroup := clusterName + "-rg"
	cmd := exec.Command("az", "group", "create", "--name", resourceGroup, "--location", region)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to create resource group: %w", err)
	}

	// Create AKS cluster
	cmd = exec.Command("az", "aks", "create",
		"--resource-group", resourceGroup,
		"--name", clusterName,
		"--node-count", "2",
		"--node-vm-size", "Standard_B2s",
		"--enable-addons", "monitoring",
		"--generate-ssh-keys")

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
		"13-chroot-escape.yaml",
		"14-secure-chroot.yaml",
		"15-highly-vulnerable.yaml",
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
