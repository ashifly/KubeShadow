package dashboard

import (
	"encoding/csv"
	"fmt"
	"strings"
	"time"
)

// generateCSV creates a CSV export of dashboard results and stats
func generateCSV(results []CommandResult, stats DashboardStats) string {
	var csvData strings.Builder
	writer := csv.NewWriter(&csvData)

	// Write summary statistics first
	writer.Write([]string{"=== KUBESHADOW DASHBOARD SUMMARY ==="})
	writer.Write([]string{"Generated", time.Now().Format(time.RFC3339)})
	writer.Write([]string{"Total Commands", fmt.Sprintf("%d", stats.TotalCommands)})
	writer.Write([]string{"Successful Runs", fmt.Sprintf("%d", stats.SuccessfulRuns)})
	writer.Write([]string{"Failed Runs", fmt.Sprintf("%d", stats.FailedRuns)})
	writer.Write([]string{"Running Commands", fmt.Sprintf("%d", stats.RunningCommands)})
	if stats.AverageTime > 0 {
		avgMs := stats.AverageTime.Nanoseconds() / 1000000
		writer.Write([]string{"Average Duration (ms)", fmt.Sprintf("%d", avgMs)})
	}
	writer.Write([]string{""}) // Empty row

	// Write command results header
	writer.Write([]string{"=== COMMAND RESULTS ==="})
	writer.Write([]string{
		"ID",
		"Command",
		"Module",
		"Status",
		"Start Time",
		"End Time",
		"Duration (ms)",
		"Exit Code",
		"Error",
		"Output Preview",
	})

	// Write command results data
	for _, result := range results {
		endTime := ""
		if result.EndTime != nil {
			endTime = result.EndTime.Format(time.RFC3339)
		}

		durationMs := result.Duration.Nanoseconds() / 1000000

		// Truncate output for CSV readability
		outputPreview := result.Output
		if len(outputPreview) > 200 {
			outputPreview = outputPreview[:200] + "..."
		}
		// Replace newlines with spaces for CSV compatibility
		outputPreview = strings.ReplaceAll(outputPreview, "\n", " ")
		outputPreview = strings.ReplaceAll(outputPreview, "\r", " ")

		writer.Write([]string{
			result.ID,
			result.Command,
			result.Module,
			result.Status,
			result.StartTime.Format(time.RFC3339),
			endTime,
			fmt.Sprintf("%d", durationMs),
			fmt.Sprintf("%d", result.ExitCode),
			result.ErrorMsg,
			outputPreview,
		})
	}

	writer.Flush()
	return csvData.String()
}

// generatePDF creates a simple PDF report (text-based for now)
func generatePDF(results []CommandResult, stats DashboardStats) []byte {
	// For now, we'll generate a simple text-based PDF using a basic PDF structure
	// In a production environment, you might want to use a proper PDF library like gofpdf

	content := generatePDFContent(results, stats)

	// Simple PDF wrapper - this creates a minimal PDF structure
	pdfHeader := `%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
>>
endobj

2 0 obj
<<
/Type /Pages
/Kids [3 0 R]
/Count 1
>>
endobj

3 0 obj
<<
/Type /Page
/Parent 2 0 R
/MediaBox [0 0 612 792]
/Contents 4 0 R
/Resources <<
/Font <<
/F1 5 0 R
>>
>>
>>
endobj

4 0 obj
<<
/Length ` + fmt.Sprintf("%d", len(content)+20) + `
>>
stream
BT
/F1 10 Tf
50 750 Td
` + content + `
ET
endstream
endobj

5 0 obj
<<
/Type /Font
/Subtype /Type1
/BaseFont /Courier
>>
endobj

xref
0 6
0000000000 65535 f 
0000000010 00000 n 
0000000053 00000 n 
0000000108 00000 n 
0000000258 00000 n 
0000000` + fmt.Sprintf("%06d", 340+len(content)) + ` 00000 n 
trailer
<<
/Size 6
/Root 1 0 R
>>
startxref
` + fmt.Sprintf("%d", 400+len(content)) + `
%%EOF`

	return []byte(pdfHeader)
}

// generatePDFContent creates the text content for the PDF
func generatePDFContent(results []CommandResult, stats DashboardStats) string {
	var content strings.Builder

	// Title and timestamp
	content.WriteString("(KubeShadow Dashboard Report) Tj\n")
	content.WriteString("0 -20 Td\n")
	content.WriteString(fmt.Sprintf("(Generated: %s) Tj\n", time.Now().Format("2006-01-02 15:04:05")))
	content.WriteString("0 -30 Td\n")

	// Statistics
	content.WriteString("(=== SUMMARY STATISTICS ===) Tj\n")
	content.WriteString("0 -20 Td\n")
	content.WriteString(fmt.Sprintf("(Total Commands: %d) Tj\n", stats.TotalCommands))
	content.WriteString("0 -15 Td\n")
	content.WriteString(fmt.Sprintf("(Successful: %d) Tj\n", stats.SuccessfulRuns))
	content.WriteString("0 -15 Td\n")
	content.WriteString(fmt.Sprintf("(Failed: %d) Tj\n", stats.FailedRuns))
	content.WriteString("0 -15 Td\n")
	content.WriteString(fmt.Sprintf("(Running: %d) Tj\n", stats.RunningCommands))
	content.WriteString("0 -15 Td\n")

	if stats.AverageTime > 0 {
		avgMs := stats.AverageTime.Nanoseconds() / 1000000
		content.WriteString(fmt.Sprintf("(Average Duration: %d ms) Tj\n", avgMs))
		content.WriteString("0 -15 Td\n")
	}

	content.WriteString("0 -30 Td\n")
	content.WriteString("(=== COMMAND RESULTS ===) Tj\n")
	content.WriteString("0 -20 Td\n")

	// Command results (limit to prevent PDF size issues)
	resultLimit := 20
	if len(results) < resultLimit {
		resultLimit = len(results)
	}

	for i := 0; i < resultLimit; i++ {
		result := results[i]

		content.WriteString(fmt.Sprintf("(Command: %s [%s]) Tj\n", result.Command, result.Module))
		content.WriteString("0 -15 Td\n")
		content.WriteString(fmt.Sprintf("(Status: %s | Duration: %d ms) Tj\n",
			result.Status, result.Duration.Nanoseconds()/1000000))
		content.WriteString("0 -15 Td\n")
		content.WriteString(fmt.Sprintf("(Started: %s) Tj\n", result.StartTime.Format("2006-01-02 15:04:05")))
		content.WriteString("0 -15 Td\n")

		if result.ErrorMsg != "" {
			// Truncate error message for PDF
			errorMsg := result.ErrorMsg
			if len(errorMsg) > 60 {
				errorMsg = errorMsg[:60] + "..."
			}
			content.WriteString(fmt.Sprintf("(Error: %s) Tj\n", errorMsg))
			content.WriteString("0 -15 Td\n")
		}

		content.WriteString("0 -10 Td\n") // Extra spacing between results
	}

	if len(results) > resultLimit {
		content.WriteString(fmt.Sprintf("(... and %d more results) Tj\n", len(results)-resultLimit))
		content.WriteString("0 -15 Td\n")
	}

	return content.String()
}
