package recon_graph

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

var ReconGraphCmd = &cobra.Command{
	Use:   "recon-graph",
	Short: "Recon Graph and Attack Chain Analysis",
	Long: `Analyze the complete recon graph and identify attack chains across all security domains.

This command provides cross-cutting capabilities for analyzing security findings:
- Builds a unified graph from all OWASP module findings
- Identifies attack chains and escalation paths
- Analyzes combined security risks
- Generates comprehensive security reports

Examples:
  kubeshadow recon-graph --analyze
  kubeshadow recon-graph --export-json graph.json
  kubeshadow recon-graph --export-dot graph.dot
  kubeshadow recon-graph --export-mermaid graph.md
  kubeshadow recon-graph --export-html report.html`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Get flags
		analyze, _ := cmd.Flags().GetBool("analyze")
		exportJSON, _ := cmd.Flags().GetString("export-json")
		exportDOT, _ := cmd.Flags().GetString("export-dot")
		exportMermaid, _ := cmd.Flags().GetString("export-mermaid")
		exportHTML, _ := cmd.Flags().GetString("export-html")
		severity, _ := cmd.Flags().GetString("severity")
		riskThreshold, _ := cmd.Flags().GetFloat64("risk-threshold")

		// Create recon graph
		graph := NewReconGraph()

		// TODO: In a real implementation, this would integrate with all OWASP modules
		// For now, we'll create a sample graph for demonstration
		oi := NewOWASPIntegration(graph)
		oi.createSampleGraph()

		// Analyze attack chains if requested
		if analyze {
			chainingEngine := NewChainingEngine(graph)

			// Find attack chains
			attackChains := chainingEngine.FindAttackChains()
			for _, chain := range attackChains {
				graph.AddAttackChain(chain)
			}

			// Find critical paths
			criticalPaths := chainingEngine.FindCriticalPaths()
			for _, path := range criticalPaths {
				graph.AddAttackChain(path)
			}

			// Display analysis results
			displayAnalysisResults(graph, severity, riskThreshold)
		}

		// Export to various formats
		visualizer := NewGraphVisualizer(graph)

		if exportJSON != "" {
			if err := visualizer.ExportToJSON(exportJSON); err != nil {
				return fmt.Errorf("failed to export JSON: %w", err)
			}
			fmt.Printf("✅ Exported graph to JSON: %s\n", exportJSON)
		}

		if exportDOT != "" {
			if err := visualizer.ExportToDOT(exportDOT); err != nil {
				return fmt.Errorf("failed to export DOT: %w", err)
			}
			fmt.Printf("✅ Exported graph to DOT: %s\n", exportDOT)
		}

		if exportMermaid != "" {
			if err := visualizer.ExportToMermaid(exportMermaid); err != nil {
				return fmt.Errorf("failed to export Mermaid: %w", err)
			}
			fmt.Printf("✅ Exported graph to Mermaid: %s\n", exportMermaid)
		}

		if exportHTML != "" {
			if err := visualizer.GenerateHTMLReport(exportHTML); err != nil {
				return fmt.Errorf("failed to export HTML: %w", err)
			}
			fmt.Printf("✅ Exported HTML report: %s\n", exportHTML)
		}

		return nil
	},
}

// displayAnalysisResults displays the analysis results
func displayAnalysisResults(graph *ReconGraph, severity string, riskThreshold float64) {
	fmt.Printf("🔍 Recon Graph Analysis Results\n")
	fmt.Printf("================================\n\n")

	// Display graph statistics
	stats := graph.GetGraphStats()
	fmt.Printf("📊 Graph Statistics:\n")
	fmt.Printf("  Total Nodes: %v\n", stats["totalNodes"])
	fmt.Printf("  Total Edges: %v\n", stats["totalEdges"])
	fmt.Printf("  Attack Chains: %v\n", stats["totalAttackChains"])
	fmt.Printf("  High Risk Nodes: %v\n", stats["highRiskNodes"])
	fmt.Printf("  High Risk Edges: %v\n", stats["highRiskEdges"])
	fmt.Printf("\n")

	// Display attack chains
	attackChains := graph.GetAttackChains()
	if len(attackChains) > 0 {
		fmt.Printf("🔗 Attack Chains:\n")

		// Filter by severity if specified
		if severity != "" {
			attackChains = graph.GetAttackChainsBySeverity(severity)
		}

		// Filter by risk threshold
		if riskThreshold > 0 {
			attackChains = graph.GetAttackChainsByRiskScore(riskThreshold)
		}

		for i, chain := range attackChains {
			severityIcon := getSeverityIcon(chain.Severity)
			fmt.Printf("  %s Chain %d (Risk: %.1f, Severity: %s)\n",
				severityIcon, i+1, chain.RiskScore, chain.Severity)
			fmt.Printf("    Description: %s\n", chain.Description)
			fmt.Printf("    Path: %s\n", strings.Join(chain.Path, " → "))
			fmt.Printf("    Steps: %d\n", len(chain.Steps))
			fmt.Printf("\n")
		}
	}

	// Display high-risk nodes
	highRiskNodes := graph.GetHighRiskNodes(7.0)
	if len(highRiskNodes) > 0 {
		fmt.Printf("🚨 High Risk Nodes:\n")
		for _, node := range highRiskNodes {
			riskIcon := getRiskIcon(node.RiskScore)
			fmt.Printf("  %s %s (%s) - Risk: %.1f\n",
				riskIcon, node.Name, node.Type, node.RiskScore)
			if len(node.Vulnerabilities) > 0 {
				fmt.Printf("    Vulnerabilities: %d\n", len(node.Vulnerabilities))
			}
		}
		fmt.Printf("\n")
	}

	// Display high-risk edges
	highRiskEdges := graph.GetHighRiskEdges(7.0)
	if len(highRiskEdges) > 0 {
		fmt.Printf("🔗 High Risk Edges:\n")
		for _, edge := range highRiskEdges {
			sourceNode := graph.Nodes[edge.Source]
			targetNode := graph.Nodes[edge.Target]

			if sourceNode != nil && targetNode != nil {
				riskIcon := getRiskIcon(edge.RiskScore)
				fmt.Printf("  %s %s → %s via %s (Risk: %.1f)\n",
					riskIcon, sourceNode.Name, targetNode.Name, edge.Type, edge.RiskScore)
			}
		}
		fmt.Printf("\n")
	}

	// Display recommendations
	visualizer := NewGraphVisualizer(graph)
	summary := visualizer.GenerateSummaryReport()
	if recommendations, ok := summary["recommendations"].([]string); ok {
		fmt.Printf("💡 Recommendations:\n")
		for i, rec := range recommendations {
			fmt.Printf("  %d. %s\n", i+1, rec)
		}
		fmt.Printf("\n")
	}
}

// Helper functions for display

func getSeverityIcon(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return "🔴"
	case "high":
		return "🟠"
	case "medium":
		return "🟡"
	case "low":
		return "🟢"
	default:
		return "⚪"
	}
}

func getRiskIcon(riskScore float64) string {
	if riskScore >= 8.0 {
		return "🔴"
	} else if riskScore >= 5.0 {
		return "🟡"
	} else {
		return "🟢"
	}
}

// createSampleGraph creates a sample graph for demonstration
func (oi *OWASPIntegration) createSampleGraph() {
	// Create sample nodes
	nodes := []*Node{
		{
			ID:         "sa-1",
			Type:       NodeTypeServiceAccount,
			Name:       "vulnerable-sa",
			Namespace:  "default",
			Properties: make(map[string]interface{}),
			RiskScore:  8.5,
			Metadata:   make(map[string]string),
		},
		{
			ID:         "role-1",
			Type:       NodeTypeClusterRole,
			Name:       "cluster-admin",
			Namespace:  "",
			Properties: make(map[string]interface{}),
			RiskScore:  9.0,
			Metadata:   make(map[string]string),
		},
		{
			ID:         "pod-1",
			Type:       NodeTypePod,
			Name:       "vulnerable-pod",
			Namespace:  "default",
			Properties: make(map[string]interface{}),
			RiskScore:  7.0,
			Vulnerabilities: []Vulnerability{
				{
					ID:          "CVE-2023-1234",
					Type:        "privilege-escalation",
					Severity:    "high",
					Title:       "Privilege Escalation Vulnerability",
					Description: "Container can escalate privileges",
					CVSS:        8.5,
					Exploitable: true,
					Remediation: "Update container image",
					Metadata:    make(map[string]string),
				},
			},
			Metadata: make(map[string]string),
		},
		{
			ID:         "secret-1",
			Type:       NodeTypeSecret,
			Name:       "admin-credentials",
			Namespace:  "default",
			Properties: make(map[string]interface{}),
			RiskScore:  9.5,
			Metadata:   make(map[string]string),
		},
		{
			ID:        "endpoint-1",
			Type:      NodeTypeEndpoint,
			Name:      "exposed-api",
			Namespace: "default",
			Properties: map[string]interface{}{
				"exposed": true,
				"port":    8080,
			},
			RiskScore: 6.0,
			Metadata:  make(map[string]string),
		},
	}

	// Create sample edges
	edges := []*Edge{
		{
			ID:         "edge-1",
			Source:     "sa-1",
			Target:     "role-1",
			Type:       EdgeTypeCanBind,
			Weight:     1.0,
			Properties: make(map[string]interface{}),
			RiskScore:  8.0,
			Metadata:   make(map[string]string),
		},
		{
			ID:         "edge-2",
			Source:     "pod-1",
			Target:     "secret-1",
			Type:       EdgeTypeCanAccess,
			Weight:     1.0,
			Properties: make(map[string]interface{}),
			RiskScore:  7.5,
			Metadata:   make(map[string]string),
		},
		{
			ID:         "edge-3",
			Source:     "endpoint-1",
			Target:     "pod-1",
			Type:       EdgeTypeCanConnect,
			Weight:     1.0,
			Properties: make(map[string]interface{}),
			RiskScore:  6.5,
			Metadata:   make(map[string]string),
		},
	}

	// Add nodes and edges to graph
	for _, node := range nodes {
		oi.graph.AddNode(node)
	}

	for _, edge := range edges {
		oi.graph.AddEdge(edge)
	}
}

func init() {
	ReconGraphCmd.Flags().Bool("analyze", false, "Analyze attack chains and security risks")
	ReconGraphCmd.Flags().String("export-json", "", "Export graph to JSON file")
	ReconGraphCmd.Flags().String("export-dot", "", "Export graph to DOT file (Graphviz)")
	ReconGraphCmd.Flags().String("export-mermaid", "", "Export graph to Mermaid file")
	ReconGraphCmd.Flags().String("export-html", "", "Export HTML report")
	ReconGraphCmd.Flags().String("severity", "", "Filter by severity (critical, high, medium, low)")
	ReconGraphCmd.Flags().Float64("risk-threshold", 0, "Filter by minimum risk score")
}
