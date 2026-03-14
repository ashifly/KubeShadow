package recon

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"kubeshadow/pkg/logger"
)

// ContainerInfo represents container-related information
type ContainerInfo struct {
	ID          string
	Name        string
	Image       string
	Status      string
	Created     time.Time
	Runtime     string
	NetworkMode string
	IPAddress   string
	Ports       []PortInfo
	Mounts      []ContainerMountInfo
	Labels      map[string]string
	Env         []string
}

// PortInfo represents container port information
type PortInfo struct {
	HostPort      string
	ContainerPort string
	Protocol      string
}

// Rename type MountInfo to ContainerMountInfo
type ContainerMountInfo struct {
	Source      string
	Destination string
	Type        string
	ReadOnly    bool
}

// GetContainerInfo retrieves information about all containers
func GetContainerInfo(ctx context.Context) ([]*ContainerInfo, error) {
	var containers []*ContainerInfo

	// Check for Docker
	if dockerContainers, err := getDockerContainers(ctx); err == nil {
		containers = append(containers, dockerContainers...)
	} else {
		logger.Debug("Docker containers not available: %v", err)
	}

	// Check for containerd
	if containerdContainers, err := getContainerdContainers(ctx); err == nil {
		containers = append(containers, containerdContainers...)
	} else {
		logger.Debug("Containerd containers not available: %v", err)
	}

	// Check for CRI-O
	if criOContainers, err := getCRIOContainers(ctx); err == nil {
		containers = append(containers, criOContainers...)
	} else {
		logger.Debug("CRI-O containers not available: %v", err)
	}

	if len(containers) == 0 {
		return nil, fmt.Errorf("no containers found")
	}

	return containers, nil
}

func getDockerContainers(ctx context.Context) ([]*ContainerInfo, error) {
	// Check if Docker socket exists
	if _, err := os.Stat("/var/run/docker.sock"); err != nil {
		return nil, fmt.Errorf("Docker socket not found: %v", err)
	}

	// Create HTTP client
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", "/var/run/docker.sock")
			},
		},
		Timeout: 5 * time.Second,
	}

	// Get containers
	req, err := http.NewRequestWithContext(ctx, "GET", "http://localhost/containers/json?all=true", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get containers: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Docker API returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %v", err)
	}

	var containers []struct {
		Id      string            `json:"Id"`
		Names   []string          `json:"Names"`
		Image   string            `json:"Image"`
		State   string            `json:"State"`
		Created string            `json:"Created"`
		Labels  map[string]string `json:"Labels"`
	}

	if err := json.Unmarshal(body, &containers); err != nil {
		return nil, fmt.Errorf("failed to parse containers: %v", err)
	}

	var result []*ContainerInfo
	for _, c := range containers {
		// Get container details
		req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("http://localhost/containers/%s/json", c.Id), nil)
		if err != nil {
			logger.Warn("Failed to create request for container %s: %v", c.Id, err)
			continue
		}

		resp, err := client.Do(req)
		if err != nil {
			logger.Warn("Failed to get details for container %s: %v", c.Id, err)
			continue
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			logger.Warn("Failed to read response for container %s: %v", c.Id, err)
			continue
		}

		var details struct {
			Config struct {
				Env []string `json:"Env"`
			} `json:"Config"`
			HostConfig struct {
				NetworkMode  string `json:"NetworkMode"`
				PortBindings map[string][]struct {
					HostPort string `json:"HostPort"`
				} `json:"PortBindings"`
			} `json:"HostConfig"`
			NetworkSettings struct {
				IPAddress string `json:"IPAddress"`
			} `json:"NetworkSettings"`
			Mounts []struct {
				Source      string `json:"Source"`
				Destination string `json:"Destination"`
				Type        string `json:"Type"`
				RW          bool   `json:"RW"`
			} `json:"Mounts"`
		}

		if err := json.Unmarshal(body, &details); err != nil {
			logger.Warn("Failed to parse details for container %s: %v", c.Id, err)
			continue
		}

		// Parse created time
		created, err := time.Parse(time.RFC3339Nano, c.Created)
		if err != nil {
			logger.Warn("Failed to parse created time for container %s: %v", c.Id, err)
			created = time.Time{}
		}

		// Parse ports
		var ports []PortInfo
		for containerPort, bindings := range details.HostConfig.PortBindings {
			for _, binding := range bindings {
				parts := strings.Split(containerPort, "/")
				if len(parts) != 2 {
					continue
				}

				ports = append(ports, PortInfo{
					HostPort:      binding.HostPort,
					ContainerPort: parts[0],
					Protocol:      parts[1],
				})
			}
		}

		// Parse mounts
		var mounts []ContainerMountInfo
		for _, m := range details.Mounts {
			mounts = append(mounts, ContainerMountInfo{
				Source:      m.Source,
				Destination: m.Destination,
				Type:        m.Type,
				ReadOnly:    !m.RW,
			})
		}

		// Create container info
		info := &ContainerInfo{
			ID:          c.Id,
			Name:        strings.TrimPrefix(c.Names[0], "/"),
			Image:       c.Image,
			Status:      c.State,
			Created:     created,
			Runtime:     "docker",
			NetworkMode: details.HostConfig.NetworkMode,
			IPAddress:   details.NetworkSettings.IPAddress,
			Ports:       ports,
			Mounts:      mounts,
			Labels:      c.Labels,
			Env:         details.Config.Env,
		}

		result = append(result, info)
	}

	return result, nil
}

func getContainerdContainers(ctx context.Context) ([]*ContainerInfo, error) {
	// Check if containerd socket exists
	if _, err := os.Stat("/run/containerd/containerd.sock"); err != nil {
		return nil, fmt.Errorf("containerd socket not found: %v", err)
	}

	// Create HTTP client
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", "/run/containerd/containerd.sock")
			},
		},
		Timeout: 5 * time.Second,
	}

	// Get containers
	req, err := http.NewRequestWithContext(ctx, "GET", "http://localhost/containers", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get containers: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("containerd API returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %v", err)
	}

	var containers []struct {
		Id      string            `json:"id"`
		Names   []string          `json:"names"`
		Image   string            `json:"image"`
		State   string            `json:"state"`
		Created string            `json:"created"`
		Labels  map[string]string `json:"labels"`
	}

	if err := json.Unmarshal(body, &containers); err != nil {
		return nil, fmt.Errorf("failed to parse containers: %v", err)
	}

	var result []*ContainerInfo
	for _, c := range containers {
		// Get container details
		req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("http://localhost/containers/%s", c.Id), nil)
		if err != nil {
			logger.Warn("Failed to create request for container %s: %v", c.Id, err)
			continue
		}

		resp, err := client.Do(req)
		if err != nil {
			logger.Warn("Failed to get details for container %s: %v", c.Id, err)
			continue
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			logger.Warn("Failed to read response for container %s: %v", c.Id, err)
			continue
		}

		var details struct {
			Config struct {
				Env []string `json:"env"`
			} `json:"config"`
			HostConfig struct {
				NetworkMode  string `json:"network_mode"`
				PortBindings map[string][]struct {
					HostPort string `json:"host_port"`
				} `json:"port_bindings"`
			} `json:"host_config"`
			NetworkSettings struct {
				IPAddress string `json:"ip_address"`
			} `json:"network_settings"`
			Mounts []struct {
				Source      string `json:"source"`
				Destination string `json:"destination"`
				Type        string `json:"type"`
				ReadOnly    bool   `json:"read_only"`
			} `json:"mounts"`
		}

		if err := json.Unmarshal(body, &details); err != nil {
			logger.Warn("Failed to parse details for container %s: %v", c.Id, err)
			continue
		}

		// Parse created time
		created, err := time.Parse(time.RFC3339Nano, c.Created)
		if err != nil {
			logger.Warn("Failed to parse created time for container %s: %v", c.Id, err)
			created = time.Time{}
		}

		// Parse ports
		var ports []PortInfo
		for containerPort, bindings := range details.HostConfig.PortBindings {
			for _, binding := range bindings {
				parts := strings.Split(containerPort, "/")
				if len(parts) != 2 {
					continue
				}

				ports = append(ports, PortInfo{
					HostPort:      binding.HostPort,
					ContainerPort: parts[0],
					Protocol:      parts[1],
				})
			}
		}

		// Parse mounts
		var mounts []ContainerMountInfo
		for _, m := range details.Mounts {
			mounts = append(mounts, ContainerMountInfo{
				Source:      m.Source,
				Destination: m.Destination,
				Type:        m.Type,
				ReadOnly:    m.ReadOnly,
			})
		}

		// Create container info
		info := &ContainerInfo{
			ID:          c.Id,
			Name:        strings.TrimPrefix(c.Names[0], "/"),
			Image:       c.Image,
			Status:      c.State,
			Created:     created,
			Runtime:     "containerd",
			NetworkMode: details.HostConfig.NetworkMode,
			IPAddress:   details.NetworkSettings.IPAddress,
			Ports:       ports,
			Mounts:      mounts,
			Labels:      c.Labels,
			Env:         details.Config.Env,
		}

		result = append(result, info)
	}

	return result, nil
}

func getCRIOContainers(ctx context.Context) ([]*ContainerInfo, error) {
	// Check if CRI-O socket exists
	if _, err := os.Stat("/var/run/crio/crio.sock"); err != nil {
		return nil, fmt.Errorf("CRI-O socket not found: %v", err)
	}

	// Create HTTP client
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", "/var/run/crio/crio.sock")
			},
		},
		Timeout: 5 * time.Second,
	}

	// Get containers
	req, err := http.NewRequestWithContext(ctx, "GET", "http://localhost/containers", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get containers: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("CRI-O API returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %v", err)
	}

	var containers []struct {
		Id      string            `json:"id"`
		Names   []string          `json:"names"`
		Image   string            `json:"image"`
		State   string            `json:"state"`
		Created string            `json:"created"`
		Labels  map[string]string `json:"labels"`
	}

	if err := json.Unmarshal(body, &containers); err != nil {
		return nil, fmt.Errorf("failed to parse containers: %v", err)
	}

	var result []*ContainerInfo
	for _, c := range containers {
		// Get container details
		req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("http://localhost/containers/%s", c.Id), nil)
		if err != nil {
			logger.Warn("Failed to create request for container %s: %v", c.Id, err)
			continue
		}

		resp, err := client.Do(req)
		if err != nil {
			logger.Warn("Failed to get details for container %s: %v", c.Id, err)
			continue
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			logger.Warn("Failed to read response for container %s: %v", c.Id, err)
			continue
		}

		var details struct {
			Config struct {
				Env []string `json:"env"`
			} `json:"config"`
			HostConfig struct {
				NetworkMode  string `json:"network_mode"`
				PortBindings map[string][]struct {
					HostPort string `json:"host_port"`
				} `json:"port_bindings"`
			} `json:"host_config"`
			NetworkSettings struct {
				IPAddress string `json:"ip_address"`
			} `json:"network_settings"`
			Mounts []struct {
				Source      string `json:"source"`
				Destination string `json:"destination"`
				Type        string `json:"type"`
				ReadOnly    bool   `json:"read_only"`
			} `json:"mounts"`
		}

		if err := json.Unmarshal(body, &details); err != nil {
			logger.Warn("Failed to parse details for container %s: %v", c.Id, err)
			continue
		}

		// Parse created time
		created, err := time.Parse(time.RFC3339Nano, c.Created)
		if err != nil {
			logger.Warn("Failed to parse created time for container %s: %v", c.Id, err)
			created = time.Time{}
		}

		// Parse ports
		var ports []PortInfo
		for containerPort, bindings := range details.HostConfig.PortBindings {
			for _, binding := range bindings {
				parts := strings.Split(containerPort, "/")
				if len(parts) != 2 {
					continue
				}

				ports = append(ports, PortInfo{
					HostPort:      binding.HostPort,
					ContainerPort: parts[0],
					Protocol:      parts[1],
				})
			}
		}

		// Parse mounts
		var mounts []ContainerMountInfo
		for _, m := range details.Mounts {
			mounts = append(mounts, ContainerMountInfo{
				Source:      m.Source,
				Destination: m.Destination,
				Type:        m.Type,
				ReadOnly:    m.ReadOnly,
			})
		}

		// Create container info
		info := &ContainerInfo{
			ID:          c.Id,
			Name:        strings.TrimPrefix(c.Names[0], "/"),
			Image:       c.Image,
			Status:      c.State,
			Created:     created,
			Runtime:     "cri-o",
			NetworkMode: details.HostConfig.NetworkMode,
			IPAddress:   details.NetworkSettings.IPAddress,
			Ports:       ports,
			Mounts:      mounts,
			Labels:      c.Labels,
			Env:         details.Config.Env,
		}

		result = append(result, info)
	}

	return result, nil
}
