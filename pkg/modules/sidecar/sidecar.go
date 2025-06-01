package sidecar

import (
	"context"
	"encoding/json"
	"fmt"
	"kubeshadow/pkg/errors"
	"kubeshadow/pkg/logger"
	"kubeshadow/pkg/modules/base"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

// SidecarConfig represents the sidecar configuration
type SidecarConfig struct {
	Image           string                  `json:"image"`
	Command         []string                `json:"command,omitempty"`
	Args            []string                `json:"args,omitempty"`
	Env             []corev1.EnvVar         `json:"env,omitempty"`
	VolumeMounts    []corev1.VolumeMount    `json:"volumeMounts,omitempty"`
	SecurityContext *corev1.SecurityContext `json:"securityContext,omitempty"`
}

// SidecarModule represents a sidecar injection module
type SidecarModule struct {
	*base.BaseModule
	mode      string
	pod       string
	namespace string
	config    string
	clientset *kubernetes.Clientset
	cmd       *cobra.Command
}

// NewSidecarModule creates a new sidecar module
func NewSidecarModule() *SidecarModule {
	cmd := &cobra.Command{
		Use:   "sidecar",
		Short: "Inject a sidecar container into a pod",
	}

	module := &SidecarModule{
		BaseModule: base.NewBaseModule("sidecar", "Kubernetes sidecar injection module"),
		cmd:        cmd,
	}

	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		return module.Execute(cmd.Context())
	}

	// Add flags
	module.cmd.Flags().StringVar(&module.mode, "mode", "api", "Injection mode (api or manifest)")
	module.cmd.Flags().StringVar(&module.pod, "pod", "", "Target pod name")
	module.cmd.Flags().StringVar(&module.namespace, "namespace", "default", "Target namespace")
	module.cmd.Flags().StringVar(&module.config, "config", "", "Path to sidecar configuration file")

	module.SetCommand(module.cmd)
	return module
}

// Command returns the cobra command for this module
func (m *SidecarModule) Command() *cobra.Command {
	return m.cmd
}

// SetCommand sets the cobra command for this module
func (m *SidecarModule) SetCommand(cmd *cobra.Command) {
	m.cmd = cmd
}

// GetStatus returns the current status of the module
func (m *SidecarModule) GetStatus() string {
	return "ready"
}

// Validate validates the sidecar module configuration
func (m *SidecarModule) Validate() error {
	if err := m.BaseModule.Validate(); err != nil {
		return err
	}

	if m.pod == "" {
		return errors.New(errors.ErrValidation, "pod name is required", nil)
	}

	if m.config == "" {
		return errors.New(errors.ErrValidation, "config path is required", nil)
	}

	if m.mode != "api" && m.mode != "manifest" {
		return errors.New(errors.ErrModule, fmt.Sprintf("unsupported mode: %s", m.mode), nil)
	}

	// Validate config file exists and is readable
	if _, err := os.Stat(m.config); os.IsNotExist(err) {
		return errors.New(errors.ErrValidation, fmt.Sprintf("config file not found: %s", m.config), err)
	}

	return nil
}

// loadConfig loads the sidecar configuration from file
func (m *SidecarModule) loadConfig() (*SidecarConfig, error) {
	data, err := os.ReadFile(m.config)
	if err != nil {
		return nil, errors.New(errors.ErrConfig, "failed to read config file", err)
	}

	var config SidecarConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, errors.New(errors.ErrConfig, "failed to parse config file", err)
	}

	if config.Image == "" {
		return nil, errors.New(errors.ErrValidation, "sidecar image is required", nil)
	}

	return &config, nil
}

// setupK8sClient sets up the Kubernetes client
func (m *SidecarModule) setupK8sClient() error {
	kubeconfig := filepath.Join(os.Getenv("HOME"), ".kube", "config")
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return errors.New(errors.ErrK8s, "failed to build kubeconfig", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return errors.New(errors.ErrK8s, "failed to create kubernetes client", err)
	}

	m.clientset = clientset
	return nil
}

// Execute runs the sidecar injection
func (m *SidecarModule) Execute(ctx context.Context) error {
	if err := m.BaseModule.Execute(ctx); err != nil {
		return err
	}

	logger.Info("Starting sidecar injection module")
	logger.Info("Using %s mode for injection", m.mode)

	// Load configuration
	config, err := m.loadConfig()
	if err != nil {
		return err
	}

	// Setup Kubernetes client
	if err := m.setupK8sClient(); err != nil {
		return err
	}

	// Get target pod
	pod, err := m.clientset.CoreV1().Pods(m.namespace).Get(ctx, m.pod, metav1.GetOptions{})
	if err != nil {
		return errors.New(errors.ErrK8s, fmt.Sprintf("failed to get pod %s", m.pod), err)
	}

	// Create sidecar container
	sidecar := corev1.Container{
		Name:            "kubeshadow-sidecar",
		Image:           config.Image,
		Command:         config.Command,
		Args:            config.Args,
		Env:             config.Env,
		VolumeMounts:    config.VolumeMounts,
		SecurityContext: config.SecurityContext,
	}

	// Add sidecar to pod
	pod.Spec.Containers = append(pod.Spec.Containers, sidecar)

	// Update pod
	_, err = m.clientset.CoreV1().Pods(m.namespace).Update(ctx, pod, metav1.UpdateOptions{})
	if err != nil {
		return errors.New(errors.ErrK8s, "failed to update pod with sidecar", err)
	}

	logger.Info("Successfully injected sidecar into pod %s", m.pod)
	return nil
}

// Cleanup performs cleanup for the sidecar module
func (m *SidecarModule) Cleanup() error {
	if m.clientset != nil {
		// Remove sidecar from pod
		ctx := context.Background()
		pod, err := m.clientset.CoreV1().Pods(m.namespace).Get(ctx, m.pod, metav1.GetOptions{})
		if err != nil {
			return errors.New(errors.ErrK8s, "failed to get pod for cleanup", err)
		}

		// Remove sidecar container
		containers := make([]corev1.Container, 0)
		for _, container := range pod.Spec.Containers {
			if container.Name != "kubeshadow-sidecar" {
				containers = append(containers, container)
			}
		}
		pod.Spec.Containers = containers

		// Update pod
		_, err = m.clientset.CoreV1().Pods(m.namespace).Update(ctx, pod, metav1.UpdateOptions{})
		if err != nil {
			return errors.New(errors.ErrK8s, "failed to remove sidecar during cleanup", err)
		}
	}

	return m.BaseModule.Cleanup()
}
