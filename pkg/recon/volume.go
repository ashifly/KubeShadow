package recon

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"kubeshadow/pkg/logger"
)

// VolumeInfo represents volume-related information
type VolumeInfo struct {
	Name        string
	Driver      string
	MountPoint  string
	Labels      map[string]string
	Options     map[string]string
	Created     time.Time
	Size        int64
	Used        int64
	Available   int64
	Usage       float64
	Mounts      []VolumeMountInfo
	Permissions string
}

// VolumeMountInfo represents volume mount information
type VolumeMountInfo struct {
	Source      string
	Destination string
	Type        string
	Options     []string
}

// GetVolumeInfo retrieves information about all volumes
func GetVolumeInfo(ctx context.Context) ([]VolumeInfo, error) {
	var volumes []VolumeInfo

	// Check for Docker volumes
	dockerVolumes, err := getDockerVolumes(ctx)
	if err != nil {
		logger.Debug("Docker volumes not available: %v", err)
	} else {
		volumes = append(volumes, dockerVolumes...)
	}

	// Check for containerd volumes
	containerdVolumes, err := getContainerdVolumes(ctx)
	if err != nil {
		logger.Debug("Containerd volumes not available: %v", err)
	} else {
		volumes = append(volumes, containerdVolumes...)
	}

	// Check for CRI-O volumes
	crioVolumes, err := getCRIOVolumes(ctx)
	if err != nil {
		logger.Debug("CRI-O volumes not available: %v", err)
	} else {
		volumes = append(volumes, crioVolumes...)
	}

	if len(volumes) == 0 {
		return nil, fmt.Errorf("no volumes found")
	}

	return volumes, nil
}

func getDockerVolumes(ctx context.Context) ([]VolumeInfo, error) {
	var volumes []VolumeInfo

	// Check if Docker socket exists
	if _, err := os.Stat("/var/run/docker.sock"); os.IsNotExist(err) {
		return nil, fmt.Errorf("Docker socket not found")
	}

	// Create HTTP client
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
		Timeout: 30 * time.Second,
	}

	// Get volumes from Docker API
	req, err := http.NewRequestWithContext(ctx, "GET", "http://localhost/volumes", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get volumes: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get volumes: %s", resp.Status)
	}

	// Parse response
	var result struct {
		Volumes []struct {
			Name       string            `json:"Name"`
			Driver     string            `json:"Driver"`
			Mountpoint string            `json:"Mountpoint"`
			Labels     map[string]string `json:"Labels"`
			Options    map[string]string `json:"Options"`
			CreatedAt  string            `json:"CreatedAt"`
		} `json:"Volumes"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %v", err)
	}

	// Convert to VolumeInfo
	for _, v := range result.Volumes {
		created, err := time.Parse(time.RFC3339, v.CreatedAt)
		if err != nil {
			logger.Warn("Failed to parse creation time for volume %s: %v", v.Name, err)
			created = time.Time{}
		}

		// Get volume stats
		size, used, available, err := getVolumeStats(v.Mountpoint)
		if err != nil {
			logger.Warn("Failed to get stats for volume %s: %v", v.Name, err)
		}

		// Get volume permissions
		permissions, err := getVolumePermissions(v.Mountpoint)
		if err != nil {
			logger.Warn("Failed to get permissions for volume %s: %v", v.Name, err)
		}

		// Get volume mounts
		mounts, err := getVolumeMounts(v.Mountpoint)
		if err != nil {
			logger.Warn("Failed to get mounts for volume %s: %v", v.Name, err)
		}

		volumes = append(volumes, VolumeInfo{
			Name:        v.Name,
			Driver:      v.Driver,
			MountPoint:  v.Mountpoint,
			Labels:      v.Labels,
			Options:     v.Options,
			Created:     created,
			Size:        size,
			Used:        used,
			Available:   available,
			Usage:       float64(used) / float64(size) * 100,
			Mounts:      mounts,
			Permissions: permissions,
		})
	}

	return volumes, nil
}

func getContainerdVolumes(ctx context.Context) ([]VolumeInfo, error) {
	var volumes []VolumeInfo

	// Check if containerd socket exists
	if _, err := os.Stat("/run/containerd/containerd.sock"); os.IsNotExist(err) {
		return nil, fmt.Errorf("containerd socket not found")
	}

	// Create HTTP client
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
		Timeout: 30 * time.Second,
	}

	// Get volumes from containerd API
	req, err := http.NewRequestWithContext(ctx, "GET", "http://localhost/volumes", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get volumes: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get volumes: %s", resp.Status)
	}

	// Parse response
	var result struct {
		Volumes []struct {
			Name       string            `json:"name"`
			Driver     string            `json:"driver"`
			Mountpoint string            `json:"mountpoint"`
			Labels     map[string]string `json:"labels"`
			Options    map[string]string `json:"options"`
			CreatedAt  string            `json:"created_at"`
		} `json:"volumes"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %v", err)
	}

	// Convert to VolumeInfo
	for _, v := range result.Volumes {
		created, err := time.Parse(time.RFC3339, v.CreatedAt)
		if err != nil {
			logger.Warn("Failed to parse creation time for volume %s: %v", v.Name, err)
			created = time.Time{}
		}

		// Get volume stats
		size, used, available, err := getVolumeStats(v.Mountpoint)
		if err != nil {
			logger.Warn("Failed to get stats for volume %s: %v", v.Name, err)
		}

		// Get volume permissions
		permissions, err := getVolumePermissions(v.Mountpoint)
		if err != nil {
			logger.Warn("Failed to get permissions for volume %s: %v", v.Name, err)
		}

		// Get volume mounts
		mounts, err := getVolumeMounts(v.Mountpoint)
		if err != nil {
			logger.Warn("Failed to get mounts for volume %s: %v", v.Name, err)
		}

		volumes = append(volumes, VolumeInfo{
			Name:        v.Name,
			Driver:      v.Driver,
			MountPoint:  v.Mountpoint,
			Labels:      v.Labels,
			Options:     v.Options,
			Created:     created,
			Size:        size,
			Used:        used,
			Available:   available,
			Usage:       float64(used) / float64(size) * 100,
			Mounts:      mounts,
			Permissions: permissions,
		})
	}

	return volumes, nil
}

func getCRIOVolumes(ctx context.Context) ([]VolumeInfo, error) {
	var volumes []VolumeInfo

	// Check if CRI-O socket exists
	if _, err := os.Stat("/var/run/crio/crio.sock"); os.IsNotExist(err) {
		return nil, fmt.Errorf("CRI-O socket not found")
	}

	// Create HTTP client
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
		Timeout: 30 * time.Second,
	}

	// Get volumes from CRI-O API
	req, err := http.NewRequestWithContext(ctx, "GET", "http://localhost/volumes", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get volumes: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get volumes: %s", resp.Status)
	}

	// Parse response
	var result struct {
		Volumes []struct {
			Name       string            `json:"name"`
			Driver     string            `json:"driver"`
			Mountpoint string            `json:"mountpoint"`
			Labels     map[string]string `json:"labels"`
			Options    map[string]string `json:"options"`
			CreatedAt  string            `json:"created_at"`
		} `json:"volumes"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %v", err)
	}

	// Convert to VolumeInfo
	for _, v := range result.Volumes {
		created, err := time.Parse(time.RFC3339, v.CreatedAt)
		if err != nil {
			logger.Warn("Failed to parse creation time for volume %s: %v", v.Name, err)
			created = time.Time{}
		}

		// Get volume stats
		size, used, available, err := getVolumeStats(v.Mountpoint)
		if err != nil {
			logger.Warn("Failed to get stats for volume %s: %v", v.Name, err)
		}

		// Get volume permissions
		permissions, err := getVolumePermissions(v.Mountpoint)
		if err != nil {
			logger.Warn("Failed to get permissions for volume %s: %v", v.Name, err)
		}

		// Get volume mounts
		mounts, err := getVolumeMounts(v.Mountpoint)
		if err != nil {
			logger.Warn("Failed to get mounts for volume %s: %v", v.Name, err)
		}

		volumes = append(volumes, VolumeInfo{
			Name:        v.Name,
			Driver:      v.Driver,
			MountPoint:  v.Mountpoint,
			Labels:      v.Labels,
			Options:     v.Options,
			Created:     created,
			Size:        size,
			Used:        used,
			Available:   available,
			Usage:       float64(used) / float64(size) * 100,
			Mounts:      mounts,
			Permissions: permissions,
		})
	}

	return volumes, nil
}

func getVolumeStats(_ string) (int64, int64, int64, error) {
	// Syscall.Statfs is not available on Windows
	// Return mock data for now
	return 0, 0, 0, fmt.Errorf("volume stats not supported on Windows")
}

func getVolumePermissions(mountpoint string) (string, error) {
	info, err := os.Stat(mountpoint)
	if err != nil {
		return "", fmt.Errorf("failed to get volume permissions: %v", err)
	}

	return info.Mode().String(), nil
}

func getVolumeMounts(mountpoint string) ([]VolumeMountInfo, error) {
	var mounts []VolumeMountInfo

	// Read /proc/mounts
	content, err := os.ReadFile("/proc/mounts")
	if err != nil {
		return nil, fmt.Errorf("failed to read /proc/mounts: %v", err)
	}

	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		// Check if this mount is related to the volume
		if strings.HasPrefix(fields[1], mountpoint) {
			mounts = append(mounts, VolumeMountInfo{
				Source:      fields[0],
				Destination: fields[1],
				Type:        fields[2],
				Options:     strings.Split(fields[3], ","),
			})
		}
	}

	return mounts, nil
}
