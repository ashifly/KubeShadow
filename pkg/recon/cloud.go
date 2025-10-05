package recon

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"kubeshadow/pkg/logger"
)

// Cloud metadata endpoints are defined inline where used

// CloudMetadata represents cloud provider metadata
type CloudMetadata struct {
	Provider    string
	InstanceID  string
	Region      string
	Zone        string
	Hostname    string
	PublicIP    string
	PrivateIP   string
	Tags        map[string]string
	Credentials map[string]string
}

// DetectCloudProvider detects the cloud provider and retrieves metadata
func DetectCloudProvider(ctx context.Context) (*CloudMetadata, error) {
	// Check AWS
	if metadata, err := checkAWS(ctx); err == nil {
		return metadata, nil
	}

	// Check GCP
	if metadata, err := checkGCP(ctx); err == nil {
		return metadata, nil
	}

	// Check Azure
	if metadata, err := checkAzure(ctx); err == nil {
		return metadata, nil
	}

	return nil, fmt.Errorf("no cloud provider detected")
}

// checkDNSResolution tests if cloud metadata hostnames can be resolved
func checkDNSResolution() {
	targets := []string{
		"metadata.google.internal",
		"instance-data.ec2.internal",
		"metadata.internal.azure",
	}

	fmt.Println("\n[+] Checking DNS resolution for cloud metadata endpoints...")
	for _, target := range targets {
		addrs, err := net.LookupHost(target)
		if err == nil {
			fmt.Printf("    [!] WARNING: %s resolves to %v\n", target, addrs)
		}
	}
}

// CloudMetadataRecon performs cloud metadata reconnaissance
func CloudMetadataRecon(ctx context.Context, stealth bool) error {
	// Removed unused client variable

	// Check DNS resolution first
	if !stealth {
		checkDNSResolution()
	}

	// Try AWS
	fmt.Println("\n[+] Checking AWS metadata...")
	_, err := checkAWS(ctx)
	if err != nil {
		fmt.Printf("    - Not running on AWS or metadata endpoint blocked\n")
	}

	// Try GCP
	fmt.Println("\n[+] Checking GCP metadata...")
	_, err = checkGCP(ctx)
	if err != nil {
		fmt.Printf("    - Not running on GCP or metadata endpoint blocked\n")
	}

	// Try Azure
	fmt.Println("\n[+] Checking Azure metadata...")
	_, err = checkAzure(ctx)
	if err != nil {
		fmt.Printf("    - Not running on Azure or metadata endpoint blocked\n")
	}

	return nil
}

func checkAWS(ctx context.Context) (*CloudMetadata, error) {
	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	// Check if we're running on AWS
	req, err := http.NewRequestWithContext(ctx, "GET", "http://169.254.169.254/latest/meta-data/", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to AWS metadata service: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("AWS metadata service returned status %d", resp.StatusCode)
	}

	// Read metadata
	metadata := &CloudMetadata{
		Provider:    "aws",
		Tags:        make(map[string]string),
		Credentials: make(map[string]string),
	}

	// Get instance ID
	if id, err := getAWSMetadata(ctx, client, "instance-id"); err == nil {
		metadata.InstanceID = id
	}

	// Get region
	if region, err := getAWSMetadata(ctx, client, "placement/region"); err == nil {
		metadata.Region = region
	}

	// Get availability zone
	if zone, err := getAWSMetadata(ctx, client, "placement/availability-zone"); err == nil {
		metadata.Zone = zone
	}

	// Get hostname
	if hostname, err := getAWSMetadata(ctx, client, "hostname"); err == nil {
		metadata.Hostname = hostname
	}

	// Get public IP
	if ip, err := getAWSMetadata(ctx, client, "public-ipv4"); err == nil {
		metadata.PublicIP = ip
	}

	// Get private IP
	if ip, err := getAWSMetadata(ctx, client, "local-ipv4"); err == nil {
		metadata.PrivateIP = ip
	}

	// Get instance tags
	if tags, err := getAWSTags(ctx, client); err == nil {
		metadata.Tags = tags
	}

	// Get credentials
	if creds, err := getAWSCredentials(ctx, client); err == nil {
		metadata.Credentials = creds
	}

	return metadata, nil
}

func getAWSMetadata(ctx context.Context, client *http.Client, path string) (string, error) {
	url := fmt.Sprintf("http://169.254.169.254/latest/meta-data/%s", path)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to get metadata: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("metadata service returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %v", err)
	}

	return string(body), nil
}

func getAWSTags(ctx context.Context, client *http.Client) (map[string]string, error) {
	tags := make(map[string]string)

	// Get instance tags
	url := "http://169.254.169.254/latest/meta-data/tags/instance"
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get tags: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("tags service returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %v", err)
	}

	// Parse tags
	tagList := strings.Split(string(body), "\n")
	for _, tag := range tagList {
		if tag == "" {
			continue
		}

		value, err := getAWSMetadata(ctx, client, fmt.Sprintf("tags/instance/%s", tag))
		if err != nil {
			logger.Warn("Failed to get tag value for %s: %v", tag, err)
			continue
		}

		tags[tag] = value
	}

	return tags, nil
}

func getAWSCredentials(ctx context.Context, client *http.Client) (map[string]string, error) {
	creds := make(map[string]string)

	// Get temporary credentials
	url := "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get credentials: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("credentials service returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %v", err)
	}

	// Get role name
	role := strings.TrimSpace(string(body))
	if role == "" {
		return nil, fmt.Errorf("no IAM role found")
	}

	// Get credentials for role
	url = fmt.Sprintf("http://169.254.169.254/latest/meta-data/iam/security-credentials/%s", role)
	req, err = http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	resp, err = client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get role credentials: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("role credentials service returned status %d", resp.StatusCode)
	}

	body, err = io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %v", err)
	}

	// Parse credentials
	var credData struct {
		AccessKeyID     string `json:"AccessKeyId"`
		SecretAccessKey string `json:"SecretAccessKey"`
		Token           string `json:"Token"`
	}

	if err := json.Unmarshal(body, &credData); err != nil {
		return nil, fmt.Errorf("failed to parse credentials: %v", err)
	}

	creds["AccessKeyId"] = credData.AccessKeyID
	creds["SecretAccessKey"] = credData.SecretAccessKey
	creds["Token"] = credData.Token

	return creds, nil
}

func checkGCP(ctx context.Context) (*CloudMetadata, error) {
	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	// Check if we're running on GCP
	req, err := http.NewRequestWithContext(ctx, "GET", "http://metadata.google.internal/computeMetadata/v1/", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("Metadata-Flavor", "Google")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to GCP metadata service: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GCP metadata service returned status %d", resp.StatusCode)
	}

	// Read metadata
	metadata := &CloudMetadata{
		Provider:    "gcp",
		Tags:        make(map[string]string),
		Credentials: make(map[string]string),
	}

	// Get instance ID
	if id, err := getGCPMetadata(ctx, client, "instance/id"); err == nil {
		metadata.InstanceID = id
	}

	// Get region
	if region, err := getGCPMetadata(ctx, client, "instance/region"); err == nil {
		metadata.Region = region
	}

	// Get zone
	if zone, err := getGCPMetadata(ctx, client, "instance/zone"); err == nil {
		metadata.Zone = zone
	}

	// Get hostname
	if hostname, err := getGCPMetadata(ctx, client, "instance/hostname"); err == nil {
		metadata.Hostname = hostname
	}

	// Get public IP
	if ip, err := getGCPMetadata(ctx, client, "instance/network-interfaces/0/access-configs/0/external-ip"); err == nil {
		metadata.PublicIP = ip
	}

	// Get private IP
	if ip, err := getGCPMetadata(ctx, client, "instance/network-interfaces/0/ip"); err == nil {
		metadata.PrivateIP = ip
	}

	// Get instance tags
	if tags, err := getGCPTags(ctx, client); err == nil {
		metadata.Tags = tags
	}

	// Get credentials
	if creds, err := getGCPCredentials(ctx, client); err == nil {
		metadata.Credentials = creds
	}

	return metadata, nil
}

func getGCPMetadata(ctx context.Context, client *http.Client, path string) (string, error) {
	url := fmt.Sprintf("http://metadata.google.internal/computeMetadata/v1/%s", path)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("Metadata-Flavor", "Google")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to get metadata: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("metadata service returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %v", err)
	}

	return string(body), nil
}

func getGCPTags(ctx context.Context, client *http.Client) (map[string]string, error) {
	tags := make(map[string]string)

	// Get instance tags
	url := "http://metadata.google.internal/computeMetadata/v1/instance/tags"
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("Metadata-Flavor", "Google")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get tags: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("tags service returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %v", err)
	}

	// Parse tags
	tagList := strings.Split(string(body), "\n")
	for _, tag := range tagList {
		if tag == "" {
			continue
		}

		tags[tag] = "true"
	}

	return tags, nil
}

func getGCPCredentials(ctx context.Context, client *http.Client) (map[string]string, error) {
	creds := make(map[string]string)

	// Get service account token
	url := "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("Metadata-Flavor", "Google")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get token: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token service returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %v", err)
	}

	// Parse token
	var tokenData struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		TokenType   string `json:"token_type"`
	}

	if err := json.Unmarshal(body, &tokenData); err != nil {
		return nil, fmt.Errorf("failed to parse token: %v", err)
	}

	creds["access_token"] = tokenData.AccessToken
	creds["token_type"] = tokenData.TokenType
	creds["expires_in"] = fmt.Sprintf("%d", tokenData.ExpiresIn)

	return creds, nil
}

func checkAzure(ctx context.Context) (*CloudMetadata, error) {
	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	// Check if we're running on Azure
	req, err := http.NewRequestWithContext(ctx, "GET", "http://169.254.169.254/metadata/instance", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("Metadata", "true")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Azure metadata service: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Azure metadata service returned status %d", resp.StatusCode)
	}

	// Read metadata
	metadata := &CloudMetadata{
		Provider:    "azure",
		Tags:        make(map[string]string),
		Credentials: make(map[string]string),
	}

	// Get instance ID
	if id, err := getAzureMetadata(ctx, client, "compute/vmId"); err == nil {
		metadata.InstanceID = id
	}

	// Get region
	if region, err := getAzureMetadata(ctx, client, "compute/location"); err == nil {
		metadata.Region = region
	}

	// Get zone
	if zone, err := getAzureMetadata(ctx, client, "compute/zone"); err == nil {
		metadata.Zone = zone
	}

	// Get hostname
	if hostname, err := getAzureMetadata(ctx, client, "compute/name"); err == nil {
		metadata.Hostname = hostname
	}

	// Get public IP
	if ip, err := getAzureMetadata(ctx, client, "network/interface/0/ipv4/ipAddress/0/publicIpAddress"); err == nil {
		metadata.PublicIP = ip
	}

	// Get private IP
	if ip, err := getAzureMetadata(ctx, client, "network/interface/0/ipv4/ipAddress/0/privateIpAddress"); err == nil {
		metadata.PrivateIP = ip
	}

	// Get instance tags
	if tags, err := getAzureTags(ctx, client); err == nil {
		metadata.Tags = tags
	}

	// Get credentials
	if creds, err := getAzureCredentials(ctx, client); err == nil {
		metadata.Credentials = creds
	}

	return metadata, nil
}

func getAzureMetadata(ctx context.Context, client *http.Client, path string) (string, error) {
	url := fmt.Sprintf("http://169.254.169.254/metadata/instance/%s?api-version=2021-02-01", path)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("Metadata", "true")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to get metadata: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("metadata service returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %v", err)
	}

	return string(body), nil
}

func getAzureTags(ctx context.Context, client *http.Client) (map[string]string, error) {
	tags := make(map[string]string)

	// Get instance tags
	url := "http://169.254.169.254/metadata/instance/compute/tags?api-version=2021-02-01"
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("Metadata", "true")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get tags: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("tags service returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %v", err)
	}

	// Parse tags
	tagList := strings.Split(string(body), ";")
	for _, tag := range tagList {
		if tag == "" {
			continue
		}

		parts := strings.Split(tag, ":")
		if len(parts) != 2 {
			continue
		}

		tags[parts[0]] = parts[1]
	}

	return tags, nil
}

func getAzureCredentials(ctx context.Context, client *http.Client) (map[string]string, error) {
	creds := make(map[string]string)

	// Get managed identity token
	url := "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-11-01&resource=https://management.azure.com/"
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("Metadata", "true")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get token: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token service returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %v", err)
	}

	// Parse token
	var tokenData struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		TokenType   string `json:"token_type"`
	}

	if err := json.Unmarshal(body, &tokenData); err != nil {
		return nil, fmt.Errorf("failed to parse token: %v", err)
	}

	creds["access_token"] = tokenData.AccessToken
	creds["token_type"] = tokenData.TokenType
	creds["expires_in"] = fmt.Sprintf("%d", tokenData.ExpiresIn)

	return creds, nil
}
