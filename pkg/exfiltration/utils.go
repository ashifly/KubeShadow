package exfiltration

import (
	"fmt"
	"os"
	"strings"
)

// GetEnvironment returns environment variables (wrapper for recon compatibility)
func GetEnvironment() []string {
	return os.Environ()
}

// SanitizeFileName sanitizes a filename to be safe for upload
func SanitizeFileName(fileName string) string {
	// Remove or replace unsafe characters
	unsafe := []string{"/", "\\", ":", "*", "?", "\"", "<", ">", "|"}
	sanitized := fileName

	for _, char := range unsafe {
		sanitized = strings.ReplaceAll(sanitized, char, "_")
	}

	// Trim spaces and dots from beginning and end
	sanitized = strings.Trim(sanitized, " .")

	// Ensure filename is not empty
	if sanitized == "" {
		sanitized = "untitled"
	}

	return sanitized
}

// ValidatePresignedURL performs basic validation on presigned URLs
func ValidatePresignedURL(url string) error {
	if url == "" {
		return fmt.Errorf("presigned URL cannot be empty")
	}

	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		return fmt.Errorf("presigned URL must start with http:// or https://")
	}

	return nil
}
