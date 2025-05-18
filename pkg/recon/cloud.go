package recon

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"
)

const (
	// Cloud metadata endpoints
	awsMetadata   = "http://169.254.169.254/latest/meta-data/"
	gcpMetadata   = "http://metadata.google.internal/computeMetadata/v1/"
	azureMetadata = "http://169.254.169.254/metadata/instance?api-version=2021-02-01"

	// Additional cloud endpoints to check
	awsIMDSv2   = "http://169.254.169.254/latest/api/token"
	gcpInternal = "http://metadata.google.internal/"
	azureIMDS   = "http://169.254.169.254/metadata/identity/oauth2/token"
)

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
	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	// Check DNS resolution first
	if !stealth {
		checkDNSResolution()
	}

	// Try AWS
	fmt.Println("\n[+] Checking AWS metadata...")
	if err := checkAWS(ctx, client, stealth); err != nil {
		fmt.Printf("    - Not running on AWS or metadata endpoint blocked\n")
	}

	// Try GCP
	fmt.Println("\n[+] Checking GCP metadata...")
	if err := checkGCP(ctx, client, stealth); err != nil {
		fmt.Printf("    - Not running on GCP or metadata endpoint blocked\n")
	}

	// Try Azure
	fmt.Println("\n[+] Checking Azure metadata...")
	if err := checkAzure(ctx, client, stealth); err != nil {
		fmt.Printf("    - Not running on Azure or metadata endpoint blocked\n")
	}

	return nil
}

func checkAWS(ctx context.Context, client *http.Client, stealth bool) error {
	// Check IMDSv2 first
	req, _ := http.NewRequestWithContext(ctx, "PUT", awsIMDSv2, nil)
	req.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "21600")
	resp, err := client.Do(req)
	if err == nil && resp.StatusCode == http.StatusOK {
		fmt.Println("    [!] WARNING: IMDSv2 token endpoint accessible!")
		resp.Body.Close()
	}

	req, _ = http.NewRequestWithContext(ctx, "GET", awsMetadata, nil)
	resp, err = client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("metadata endpoint returned %d", resp.StatusCode)
	}

	fmt.Println("    [+] AWS metadata endpoint accessible!")

	if !stealth {
		// Try to get instance identity
		req, _ = http.NewRequestWithContext(ctx, "GET", awsMetadata+"identity-credentials/ec2/security-credentials/", nil)
		resp, err = client.Do(req)
		if err == nil && resp.StatusCode == http.StatusOK {
			fmt.Println("    [!] WARNING: EC2 instance credentials accessible!")
		}
	}

	return nil
}

func checkGCP(ctx context.Context, client *http.Client, stealth bool) error {
	// Check base metadata endpoint first
	req, _ := http.NewRequestWithContext(ctx, "GET", gcpInternal, nil)
	req.Header.Set("Metadata-Flavor", "Google")
	resp, err := client.Do(req)
	if err == nil && resp.StatusCode == http.StatusOK {
		fmt.Println("    [!] WARNING: GCP internal DNS endpoint accessible!")
		resp.Body.Close()
	}

	req, _ = http.NewRequestWithContext(ctx, "GET", gcpMetadata, nil)
	req.Header.Set("Metadata-Flavor", "Google")
	resp, err = client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("metadata endpoint returned %d", resp.StatusCode)
	}

	fmt.Println("    [+] GCP metadata endpoint accessible!")

	if !stealth {
		// Try to get service account tokens
		req, _ = http.NewRequestWithContext(ctx, "GET", gcpMetadata+"instance/service-accounts/default/token", nil)
		req.Header.Set("Metadata-Flavor", "Google")
		resp, err = client.Do(req)
		if err == nil && resp.StatusCode == http.StatusOK {
			fmt.Println("    [!] WARNING: Service account tokens accessible!")
		}
	}

	return nil
}

func checkAzure(ctx context.Context, client *http.Client, stealth bool) error {
	// Check managed identity endpoint first
	req, _ := http.NewRequestWithContext(ctx, "GET", azureIMDS, nil)
	req.Header.Set("Metadata", "true")
	resp, err := client.Do(req)
	if err == nil && resp.StatusCode == http.StatusOK {
		fmt.Println("    [!] WARNING: Azure managed identity endpoint accessible!")
		resp.Body.Close()
	}

	req, _ = http.NewRequestWithContext(ctx, "GET", azureMetadata, nil)
	req.Header.Set("Metadata", "true")
	resp, err = client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("metadata endpoint returned %d", resp.StatusCode)
	}

	fmt.Println("    [+] Azure metadata endpoint accessible!")

	if !stealth {
		// Try to get managed identity
		req, _ = http.NewRequestWithContext(ctx, "GET", azureMetadata+"identity/oauth2/token", nil)
		req.Header.Set("Metadata", "true")
		resp, err = client.Do(req)
		if err == nil && resp.StatusCode == http.StatusOK {
			fmt.Println("    [!] WARNING: Managed identity tokens accessible!")
		}
	}

	return nil
}
