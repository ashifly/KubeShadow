package kubelet

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// Pod represents basic pod information from kubelet API
type Pod struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	UID       string `json:"uid"`
}

type podList struct {
	Items []struct {
		Metadata struct {
			Name      string `json:"name"`
			Namespace string `json:"namespace"`
			UID       string `json:"uid"`
		} `json:"metadata"`
	} `json:"items"`
}

// InsecureTLS returns an insecure TLS configuration for testing kubelet APIs
func InsecureTLS() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
}

// SecureTLS returns a secure TLS configuration that verifies certificates
func SecureTLS() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
}

// ListPods retrieves pods from the kubelet API
func ListPods(client *http.Client, baseURL string) ([]Pod, error) {
	resp, err := client.Get(fmt.Sprintf("%s/pods", baseURL))
	if err != nil {
		return nil, fmt.Errorf("failed to get pods: %v", err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			err = fmt.Errorf("failed to close response body: %v", cerr)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var list podList
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		return nil, fmt.Errorf("failed to decode pod list: %v", err)
	}

	var pods []Pod
	for _, item := range list.Items {
		pods = append(pods, Pod{
			Name:      item.Metadata.Name,
			Namespace: item.Metadata.Namespace,
			UID:       item.Metadata.UID,
		})
	}

	return pods, nil
}

// GetPodLogs retrieves logs for a specific pod
func GetPodLogs(client *http.Client, baseURL string, pod Pod) (string, error) {
	logURL := fmt.Sprintf("%s/containerLogs/%s/%s", baseURL, pod.Namespace, pod.Name)
	resp, err := client.Get(logURL)
	if err != nil {
		return "", fmt.Errorf("failed to get logs: %v", err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			err = fmt.Errorf("failed to close response body: %v", cerr)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to get logs, status: %d", resp.StatusCode)
	}

	logs, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read logs: %v", err)
	}

	return string(logs), nil
}

// TryExec attempts to execute a command in a pod via kubelet API
func TryExec(client *http.Client, baseURL string, pod Pod, command []string) (string, error) {
	execURL := fmt.Sprintf("%s/exec/%s/%s?%s",
		baseURL,
		pod.Namespace,
		pod.Name,
		buildExecQuery(command),
	)

	resp, err := client.Post(execURL, "application/json", nil)
	if err != nil {
		return "", fmt.Errorf("failed to exec command: %v", err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			err = fmt.Errorf("failed to close response body: %v", cerr)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("exec failed with status: %d", resp.StatusCode)
	}

	output, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read exec output: %v", err)
	}

	return string(output), nil
}

// buildExecQuery builds the query parameters for exec command
func buildExecQuery(command []string) string {
	params := url.Values{}
	for _, cmd := range command {
		params.Add("command", cmd)
	}
	params.Add("stdout", "1")
	params.Add("stderr", "1")
	return params.Encode()
}
