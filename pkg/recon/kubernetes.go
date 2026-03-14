package recon

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"kubeshadow/pkg/logger"
)

// KubernetesInfo represents Kubernetes-related information
type KubernetesInfo struct {
	Version        string
	ClusterName    string
	Namespace      string
	PodName        string
	NodeName       string
	ServiceAccount string
	Config         map[string]string
	Secrets        map[string]string
}

// GetKubernetesInfo retrieves Kubernetes-related information
func GetKubernetesInfo(ctx context.Context) (*KubernetesInfo, error) {
	info := &KubernetesInfo{
		Config:  make(map[string]string),
		Secrets: make(map[string]string),
	}

	// Check if we're running in a Kubernetes cluster
	if !isRunningInKubernetes() {
		return nil, fmt.Errorf("not running in a Kubernetes cluster")
	}

	// Get Kubernetes version
	if version, err := getKubernetesVersion(ctx); err == nil {
		info.Version = version
	}

	// Get cluster name
	if name, err := getClusterName(ctx); err == nil {
		info.ClusterName = name
	}

	// Get namespace
	if namespace, err := getNamespace(); err == nil {
		info.Namespace = namespace
	}

	// Get pod name
	if podName, err := getPodName(); err == nil {
		info.PodName = podName
	}

	// Get node name
	if nodeName, err := getNodeName(); err == nil {
		info.NodeName = nodeName
	}

	// Get service account
	if sa, err := getServiceAccount(); err == nil {
		info.ServiceAccount = sa
	}

	// Get Kubernetes configuration
	if config, err := getKubernetesConfig(ctx); err == nil {
		info.Config = config
	}

	// Get Kubernetes secrets
	if secrets, err := getKubernetesSecrets(ctx); err == nil {
		info.Secrets = secrets
	}

	return info, nil
}

func isRunningInKubernetes() bool {
	// Check for Kubernetes environment variables
	if os.Getenv("KUBERNETES_SERVICE_HOST") == "" {
		return false
	}

	// Check for service account token
	if _, err := os.Stat("/var/run/secrets/kubernetes.io/serviceaccount/token"); err != nil {
		return false
	}

	return true
}

func getKubernetesVersion(ctx context.Context) (string, error) {
	// Read version from service account token
	tokenPath := "/var/run/secrets/kubernetes.io/serviceaccount/token"
	token, err := os.ReadFile(tokenPath)
	if err != nil {
		return "", fmt.Errorf("failed to read service account token: %v", err)
	}

	// Make request to Kubernetes API
	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	req, err := http.NewRequestWithContext(ctx, "GET", "https://kubernetes.default.svc/version", nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", string(token)))

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to get Kubernetes version: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("Kubernetes API returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %v", err)
	}

	var version struct {
		GitVersion string `json:"gitVersion"`
	}

	if err := json.Unmarshal(body, &version); err != nil {
		return "", fmt.Errorf("failed to parse version: %v", err)
	}

	return version.GitVersion, nil
}

func getClusterName(ctx context.Context) (string, error) {
	// Read cluster name from service account token
	tokenPath := "/var/run/secrets/kubernetes.io/serviceaccount/token"
	token, err := os.ReadFile(tokenPath)
	if err != nil {
		return "", fmt.Errorf("failed to read service account token: %v", err)
	}

	// Make request to Kubernetes API
	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	req, err := http.NewRequestWithContext(ctx, "GET", "https://kubernetes.default.svc/api/v1/namespaces/kube-system/configmaps/kubeadm-config", nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", string(token)))

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to get cluster name: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("Kubernetes API returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %v", err)
	}

	var configMap struct {
		Data struct {
			ClusterConfiguration string `json:"clusterConfiguration"`
		} `json:"data"`
	}

	if err := json.Unmarshal(body, &configMap); err != nil {
		return "", fmt.Errorf("failed to parse config map: %v", err)
	}

	var clusterConfig struct {
		ClusterName string `json:"clusterName"`
	}

	if err := json.Unmarshal([]byte(configMap.Data.ClusterConfiguration), &clusterConfig); err != nil {
		return "", fmt.Errorf("failed to parse cluster configuration: %v", err)
	}

	return clusterConfig.ClusterName, nil
}

func getNamespace() (string, error) {
	// Read namespace from service account
	namespacePath := "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
	namespace, err := os.ReadFile(namespacePath)
	if err != nil {
		return "", fmt.Errorf("failed to read namespace: %v", err)
	}

	return string(namespace), nil
}

func getPodName() (string, error) {
	// Get pod name from environment variable
	podName := os.Getenv("HOSTNAME")
	if podName == "" {
		return "", fmt.Errorf("HOSTNAME environment variable not set")
	}

	return podName, nil
}

func getNodeName() (string, error) {
	// Get node name from environment variable
	nodeName := os.Getenv("NODE_NAME")
	if nodeName == "" {
		return "", fmt.Errorf("NODE_NAME environment variable not set")
	}

	return nodeName, nil
}

func getServiceAccount() (string, error) {
	// Read service account from service account token
	tokenPath := "/var/run/secrets/kubernetes.io/serviceaccount/token"
	token, err := os.ReadFile(tokenPath)
	if err != nil {
		return "", fmt.Errorf("failed to read service account token: %v", err)
	}

	// Parse JWT token to get service account name
	parts := strings.Split(string(token), ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("invalid JWT token format")
	}

	// Decode payload
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("failed to decode JWT payload: %v", err)
	}

	var claims struct {
		Sub string `json:"sub"`
	}

	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", fmt.Errorf("failed to parse JWT claims: %v", err)
	}

	// Extract service account name from subject
	parts = strings.Split(claims.Sub, ":")
	if len(parts) != 4 {
		return "", fmt.Errorf("invalid subject format")
	}

	return parts[3], nil
}

func getKubernetesConfig(ctx context.Context) (map[string]string, error) {
	config := make(map[string]string)

	// Read service account token
	tokenPath := "/var/run/secrets/kubernetes.io/serviceaccount/token"
	token, err := os.ReadFile(tokenPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read service account token: %v", err)
	}

	// Make request to Kubernetes API
	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	// Get namespace
	namespace, err := getNamespace()
	if err != nil {
		return nil, fmt.Errorf("failed to get namespace: %v", err)
	}

	// Get config maps
	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("https://kubernetes.default.svc/api/v1/namespaces/%s/configmaps", namespace), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", string(token)))

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get config maps: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Kubernetes API returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %v", err)
	}

	var configMapList struct {
		Items []struct {
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
			Data map[string]string `json:"data"`
		} `json:"items"`
	}

	if err := json.Unmarshal(body, &configMapList); err != nil {
		return nil, fmt.Errorf("failed to parse config map list: %v", err)
	}

	// Process config maps
	for _, item := range configMapList.Items {
		for key, value := range item.Data {
			config[fmt.Sprintf("%s/%s", item.Metadata.Name, key)] = value
		}
	}

	return config, nil
}

func getKubernetesSecrets(ctx context.Context) (map[string]string, error) {
	secrets := make(map[string]string)

	// Read service account token
	tokenPath := "/var/run/secrets/kubernetes.io/serviceaccount/token"
	token, err := os.ReadFile(tokenPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read service account token: %v", err)
	}

	// Make request to Kubernetes API
	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	// Get namespace
	namespace, err := getNamespace()
	if err != nil {
		return nil, fmt.Errorf("failed to get namespace: %v", err)
	}

	// Get secrets
	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("https://kubernetes.default.svc/api/v1/namespaces/%s/secrets", namespace), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", string(token)))

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get secrets: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Kubernetes API returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %v", err)
	}

	var secretList struct {
		Items []struct {
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
			Data map[string]string `json:"data"`
		} `json:"items"`
	}

	if err := json.Unmarshal(body, &secretList); err != nil {
		return nil, fmt.Errorf("failed to parse secret list: %v", err)
	}

	// Process secrets
	for _, item := range secretList.Items {
		for key, value := range item.Data {
			// Decode base64 value
			decoded, err := base64.StdEncoding.DecodeString(value)
			if err != nil {
				logger.Warn("Failed to decode secret value for %s/%s: %v", item.Metadata.Name, key, err)
				continue
			}

			secrets[fmt.Sprintf("%s/%s", item.Metadata.Name, key)] = string(decoded)
		}
	}

	return secrets, nil
}
