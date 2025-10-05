package dashboard

import (
	"encoding/json"
	"log"
	"time"
)

// ModuleResult represents a result from any OWASP module
type ModuleResult struct {
	Module    string                 `json:"module"`
	Command   string                 `json:"command"`
	Status    string                 `json:"status"`
	Findings  []Finding              `json:"findings"`
	Summary   ModuleSummary          `json:"summary"`
	Output    string                 `json:"output"`
	Error     string                 `json:"error,omitempty"`
	Timestamp time.Time              `json:"timestamp"`
	Duration  time.Duration          `json:"duration"`
	Metadata  map[string]interface{} `json:"metadata"`
}

// Finding represents a security finding
type Finding struct {
	ID          string  `json:"id"`
	Type        string  `json:"type"`
	Severity    string  `json:"severity"`
	Title       string  `json:"title"`
	Description string  `json:"description"`
	Resource    string  `json:"resource"`
	Namespace   string  `json:"namespace"`
	RiskScore   float64 `json:"riskScore"`
	Remediation string  `json:"remediation"`
}

// ModuleSummary represents summary statistics for a module
type ModuleSummary struct {
	TotalFindings    int     `json:"totalFindings"`
	CriticalCount    int     `json:"criticalCount"`
	HighCount        int     `json:"highCount"`
	MediumCount      int     `json:"mediumCount"`
	LowCount         int     `json:"lowCount"`
	CoverageScore    float64 `json:"coverageScore,omitempty"`
	RiskScore        float64 `json:"riskScore,omitempty"`
	ResourcesScanned int     `json:"resourcesScanned,omitempty"`
}

// PublishModuleResult publishes a module result to the dashboard
func PublishModuleResult(module, command string, result interface{}, output string, err error) {
	if !GetInstance().enabled {
		return
	}

	moduleResult := &ModuleResult{
		Module:    module,
		Command:   command,
		Status:    "completed",
		Output:    output,
		Timestamp: time.Now(),
		Metadata:  make(map[string]interface{}),
	}

	if err != nil {
		moduleResult.Status = "failed"
		moduleResult.Error = err.Error()
	}

	// Extract findings and summary from result
	if result != nil {
		extractFindingsAndSummary(result, moduleResult)
	}

	// Publish to dashboard
	GetInstance().publishModuleResult(moduleResult)
}

// extractFindingsAndSummary extracts findings and summary from various result types
func extractFindingsAndSummary(result interface{}, moduleResult *ModuleResult) {
	// Try to extract findings from common result types
	switch r := result.(type) {
	case map[string]interface{}:
		// Handle JSON-like results
		if findings, ok := r["findings"].([]interface{}); ok {
			for _, f := range findings {
				if finding, ok := f.(map[string]interface{}); ok {
					moduleResult.Findings = append(moduleResult.Findings, Finding{
						ID:          getString(finding, "id"),
						Type:        getString(finding, "type"),
						Severity:    getString(finding, "severity"),
						Title:       getString(finding, "title"),
						Description: getString(finding, "description"),
						Resource:    getString(finding, "resource"),
						Namespace:   getString(finding, "namespace"),
						RiskScore:   getFloat64(finding, "riskScore"),
						Remediation: getString(finding, "remediation"),
					})
				}
			}
		}

		// Extract summary
		if summary, ok := r["summary"].(map[string]interface{}); ok {
			moduleResult.Summary = ModuleSummary{
				TotalFindings:    getInt(summary, "totalFindings"),
				CriticalCount:    getInt(summary, "criticalCount"),
				HighCount:        getInt(summary, "highCount"),
				MediumCount:      getInt(summary, "mediumCount"),
				LowCount:         getInt(summary, "lowCount"),
				CoverageScore:    getFloat64(summary, "coverageScore"),
				RiskScore:        getFloat64(summary, "riskScore"),
				ResourcesScanned: getInt(summary, "resourcesScanned"),
			}
		}
	}
}

// Helper functions for type conversion
func getString(m map[string]interface{}, key string) string {
	if val, ok := m[key].(string); ok {
		return val
	}
	return ""
}

func getInt(m map[string]interface{}, key string) int {
	if val, ok := m[key].(int); ok {
		return val
	}
	if val, ok := m[key].(float64); ok {
		return int(val)
	}
	return 0
}

func getFloat64(m map[string]interface{}, key string) float64 {
	if val, ok := m[key].(float64); ok {
		return val
	}
	if val, ok := m[key].(int); ok {
		return float64(val)
	}
	return 0.0
}

// publishModuleResult publishes a module result to connected clients
func (d *Dashboard) publishModuleResult(result *ModuleResult) {
	d.clientMutex.Lock()
	defer d.clientMutex.Unlock()

	// Convert to JSON
	data, err := json.Marshal(result)
	if err != nil {
		log.Printf("Error marshaling module result: %v", err)
		return
	}

	// Send to all connected WebSocket clients
	for client := range d.clients {
		if err := client.WriteMessage(1, data); err != nil {
			log.Printf("Error sending module result to client: %v", err)
			delete(d.clients, client)
			client.Close()
		}
	}

	log.Printf("📊 Published %s module result to dashboard", result.Module)
}
