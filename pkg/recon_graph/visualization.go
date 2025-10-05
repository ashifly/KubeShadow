package recon_graph

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// GraphVisualizer represents the graph visualization engine
type GraphVisualizer struct {
	graph *ReconGraph
}

// NewGraphVisualizer creates a new graph visualizer
func NewGraphVisualizer(graph *ReconGraph) *GraphVisualizer {
	return &GraphVisualizer{
		graph: graph,
	}
}

// ExportToJSON exports the graph to JSON format
func (gv *GraphVisualizer) ExportToJSON(filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(gv.graph)
}

// ExportToDOT exports the graph to DOT format for Graphviz
func (gv *GraphVisualizer) ExportToDOT(filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	// Write DOT header
	fmt.Fprintf(file, "digraph ReconGraph {\n")
	fmt.Fprintf(file, "  rankdir=LR;\n")
	fmt.Fprintf(file, "  node [shape=box, style=filled];\n")
	fmt.Fprintf(file, "  edge [color=gray];\n\n")

	// Write nodes
	for _, node := range gv.graph.Nodes {
		color := gv.getNodeColor(node)
		shape := gv.getNodeShape(node)
		fmt.Fprintf(file, "  \"%s\" [label=\"%s\\n%s\", fillcolor=\"%s\", shape=\"%s\"];\n",
			node.ID, node.Name, node.Type, color, shape)
	}

	// Write edges
	for _, edge := range gv.graph.Edges {
		color := gv.getEdgeColor(edge)
		style := gv.getEdgeStyle(edge)
		fmt.Fprintf(file, "  \"%s\" -> \"%s\" [label=\"%s\", color=\"%s\", style=\"%s\"];\n",
			edge.Source, edge.Target, edge.Type, color, style)
	}

	// Write attack chains
	if len(gv.graph.AttackChains) > 0 {
		fmt.Fprintf(file, "\n  // Attack Chains\n")
		for i, chain := range gv.graph.AttackChains {
			fmt.Fprintf(file, "  subgraph cluster_chain_%d {\n", i)
			fmt.Fprintf(file, "    label=\"Attack Chain %d (Risk: %.1f)\";\n", i+1, chain.RiskScore)
			fmt.Fprintf(file, "    style=filled;\n")
			fmt.Fprintf(file, "    fillcolor=lightcoral;\n")

			for j, nodeID := range chain.Path {
				if j < len(chain.Path)-1 {
					nextNodeID := chain.Path[j+1]
					fmt.Fprintf(file, "    \"%s\" -> \"%s\" [color=red, penwidth=3];\n", nodeID, nextNodeID)
				}
			}
			fmt.Fprintf(file, "  }\n")
		}
	}

	fmt.Fprintf(file, "}\n")
	return nil
}

// ExportToMermaid exports the graph to Mermaid format
func (gv *GraphVisualizer) ExportToMermaid(filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	// Write Mermaid header
	fmt.Fprintf(file, "graph TD\n")

	// Write nodes
	for _, node := range gv.graph.Nodes {
		fmt.Fprintf(file, "  %s[%s<br/>%s]:::node_%s\n",
			gv.sanitizeID(node.ID), node.Name, node.Type, strings.ToLower(string(node.Type)))
	}

	// Write edges
	for _, edge := range gv.graph.Edges {
		fmt.Fprintf(file, "  %s -->|%s| %s\n",
			gv.sanitizeID(edge.Source), edge.Type, gv.sanitizeID(edge.Target))
	}

	// Write attack chains
	if len(gv.graph.AttackChains) > 0 {
		fmt.Fprintf(file, "\n  %% Attack Chains\n")
		for i, chain := range gv.graph.AttackChains {
			fmt.Fprintf(file, "  subgraph chain_%d[\"Attack Chain %d (Risk: %.1f)\"]\n", i, i+1, chain.RiskScore)
			for j, nodeID := range chain.Path {
				if j < len(chain.Path)-1 {
					nextNodeID := chain.Path[j+1]
					fmt.Fprintf(file, "    %s --> %s\n",
						gv.sanitizeID(nodeID), gv.sanitizeID(nextNodeID))
				}
			}
			fmt.Fprintf(file, "  end\n")
		}
	}

	// Write styles
	fmt.Fprintf(file, "\n  classDef node_pod fill:#e1f5fe,stroke:#01579b,stroke-width:2px\n")
	fmt.Fprintf(file, "  classDef node_serviceaccount fill:#f3e5f5,stroke:#4a148c,stroke-width:2px\n")
	fmt.Fprintf(file, "  classDef node_secret fill:#ffebee,stroke:#b71c1c,stroke-width:2px\n")
	fmt.Fprintf(file, "  classDef node_role fill:#e8f5e8,stroke:#1b5e20,stroke-width:2px\n")
	fmt.Fprintf(file, "  classDef node_endpoint fill:#fff3e0,stroke:#e65100,stroke-width:2px\n")
	fmt.Fprintf(file, "  classDef node_loadbalancer fill:#fce4ec,stroke:#880e4f,stroke-width:2px\n")

	return nil
}

// GenerateHTMLReport generates an HTML report of the graph
func (gv *GraphVisualizer) GenerateHTMLReport(filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	// Write HTML header
	fmt.Fprintf(file, `<!DOCTYPE html>
<html>
<head>
    <title>KubeShadow Recon Graph Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #f0f0f0; padding: 20px; border-radius: 5px; }
        .stats { display: flex; gap: 20px; margin: 20px 0; }
        .stat-box { background-color: #e8f5e8; padding: 15px; border-radius: 5px; text-align: center; }
        .high-risk { background-color: #ffebee; }
        .medium-risk { background-color: #fff3e0; }
        .low-risk { background-color: #e8f5e8; }
        .attack-chain { background-color: #fce4ec; padding: 15px; margin: 10px 0; border-radius: 5px; }
        .node-list { display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 15px; }
        .node-item { border: 1px solid #ddd; padding: 10px; border-radius: 5px; }
        .edge-list { margin: 20px 0; }
        .edge-item { background-color: #f5f5f5; padding: 10px; margin: 5px 0; border-radius: 3px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>KubeShadow Recon Graph Report</h1>
        <p>Generated at: %s</p>
    </div>
`, time.Now().Format("2006-01-02 15:04:05"))

	// Write statistics
	stats := gv.graph.GetGraphStats()
	fmt.Fprintf(file, `
    <div class="stats">
        <div class="stat-box">
            <h3>Total Nodes</h3>
            <p>%v</p>
        </div>
        <div class="stat-box">
            <h3>Total Edges</h3>
            <p>%v</p>
        </div>
        <div class="stat-box">
            <h3>Attack Chains</h3>
            <p>%v</p>
        </div>
        <div class="stat-box">
            <h3>High Risk Nodes</h3>
            <p>%v</p>
        </div>
    </div>
`, stats["totalNodes"], stats["totalEdges"], stats["totalAttackChains"], stats["highRiskNodes"])

	// Write attack chains
	if len(gv.graph.AttackChains) > 0 {
		fmt.Fprintf(file, `
    <h2>Attack Chains</h2>
`)
		for i, chain := range gv.graph.AttackChains {
			riskClass := "low-risk"
			if chain.RiskScore >= 8.0 {
				riskClass = "high-risk"
			} else if chain.RiskScore >= 5.0 {
				riskClass = "medium-risk"
			}

			fmt.Fprintf(file, `
    <div class="attack-chain %s">
        <h3>Attack Chain %d (Risk Score: %.1f, Severity: %s)</h3>
        <p><strong>Description:</strong> %s</p>
        <p><strong>Path:</strong> %s</p>
        <h4>Steps:</h4>
        <ol>
`, riskClass, i+1, chain.RiskScore, chain.Severity, chain.Description, strings.Join(chain.Path, " → "))

			for _, step := range chain.Steps {
				fmt.Fprintf(file, `
            <li><strong>Step %d:</strong> %s (Risk: %.1f)</li>
`, step.Step, step.Description, step.RiskScore)
			}

			fmt.Fprintf(file, `
        </ol>
    </div>
`)
		}
	}

	// Write high-risk nodes
	highRiskNodes := gv.graph.GetHighRiskNodes(7.0)
	if len(highRiskNodes) > 0 {
		fmt.Fprintf(file, `
    <h2>High Risk Nodes</h2>
    <div class="node-list">
`)
		for _, node := range highRiskNodes {
			riskClass := "low-risk"
			if node.RiskScore >= 8.0 {
				riskClass = "high-risk"
			} else if node.RiskScore >= 5.0 {
				riskClass = "medium-risk"
			}

			fmt.Fprintf(file, `
        <div class="node-item %s">
            <h4>%s (%s)</h4>
            <p><strong>Namespace:</strong> %s</p>
            <p><strong>Risk Score:</strong> %.1f</p>
            <p><strong>Vulnerabilities:</strong> %d</p>
        </div>
`, riskClass, node.Name, node.Type, node.Namespace, node.RiskScore, len(node.Vulnerabilities))
		}
		fmt.Fprintf(file, `
    </div>
`)
	}

	// Write high-risk edges
	highRiskEdges := gv.graph.GetHighRiskEdges(7.0)
	if len(highRiskEdges) > 0 {
		fmt.Fprintf(file, `
    <h2>High Risk Edges</h2>
    <div class="edge-list">
`)
		for _, edge := range highRiskEdges {
			sourceNode := gv.graph.Nodes[edge.Source]
			targetNode := gv.graph.Nodes[edge.Target]

			if sourceNode != nil && targetNode != nil {
				fmt.Fprintf(file, `
        <div class="edge-item">
            <strong>%s</strong> → <strong>%s</strong> via <strong>%s</strong> (Risk: %.1f)
        </div>
`, sourceNode.Name, targetNode.Name, edge.Type, edge.RiskScore)
			}
		}
		fmt.Fprintf(file, `
    </div>
`)
	}

	fmt.Fprintf(file, `
</body>
</html>
`)

	return nil
}

// Helper methods for visualization

func (gv *GraphVisualizer) getNodeColor(node *Node) string {
	if node.RiskScore >= 8.0 {
		return "red"
	} else if node.RiskScore >= 5.0 {
		return "orange"
	} else {
		return "lightblue"
	}
}

func (gv *GraphVisualizer) getNodeShape(node *Node) string {
	switch node.Type {
	case NodeTypeServiceAccount:
		return "ellipse"
	case NodeTypeSecret:
		return "diamond"
	case NodeTypeRole, NodeTypeClusterRole:
		return "hexagon"
	case NodeTypeEndpoint:
		return "triangle"
	case NodeTypeLoadBalancer:
		return "house"
	default:
		return "box"
	}
}

func (gv *GraphVisualizer) getMermaidNodeShape(node *Node) string {
	switch node.Type {
	case NodeTypeServiceAccount:
		return "ellipse"
	case NodeTypeSecret:
		return "diamond"
	case NodeTypeRole, NodeTypeClusterRole:
		return "hexagon"
	case NodeTypeEndpoint:
		return "triangle"
	case NodeTypeLoadBalancer:
		return "house"
	default:
		return "rect"
	}
}

func (gv *GraphVisualizer) getEdgeColor(edge *Edge) string {
	if edge.RiskScore >= 8.0 {
		return "red"
	} else if edge.RiskScore >= 5.0 {
		return "orange"
	} else {
		return "gray"
	}
}

func (gv *GraphVisualizer) getEdgeStyle(edge *Edge) string {
	if edge.RiskScore >= 8.0 {
		return "bold"
	} else if edge.RiskScore >= 5.0 {
		return "dashed"
	} else {
		return "solid"
	}
}

func (gv *GraphVisualizer) sanitizeID(id string) string {
	// Replace special characters with underscores
	id = strings.ReplaceAll(id, "-", "_")
	id = strings.ReplaceAll(id, ".", "_")
	id = strings.ReplaceAll(id, ":", "_")
	return id
}

// GenerateSummaryReport generates a summary report
func (gv *GraphVisualizer) GenerateSummaryReport() map[string]interface{} {
	stats := gv.graph.GetGraphStats()

	// Add attack chain analysis
	attackChains := gv.graph.GetAttackChains()
	criticalChains := gv.graph.GetAttackChainsBySeverity("critical")
	highChains := gv.graph.GetAttackChainsBySeverity("high")

	summary := map[string]interface{}{
		"graph_stats": stats,
		"attack_chains": map[string]interface{}{
			"total":    len(attackChains),
			"critical": len(criticalChains),
			"high":     len(highChains),
		},
		"recommendations": gv.generateRecommendations(),
	}

	return summary
}

func (gv *GraphVisualizer) generateRecommendations() []string {
	var recommendations []string

	// Analyze attack chains
	criticalChains := gv.graph.GetAttackChainsBySeverity("critical")
	if len(criticalChains) > 0 {
		recommendations = append(recommendations, "Address critical attack chains immediately")
		recommendations = append(recommendations, "Implement additional security controls for critical paths")
	}

	// Analyze high-risk nodes
	highRiskNodes := gv.graph.GetHighRiskNodes(8.0)
	if len(highRiskNodes) > 0 {
		recommendations = append(recommendations, "Review and secure high-risk nodes")
		recommendations = append(recommendations, "Implement monitoring for high-risk resources")
	}

	// Analyze high-risk edges
	highRiskEdges := gv.graph.GetHighRiskEdges(8.0)
	if len(highRiskEdges) > 0 {
		recommendations = append(recommendations, "Review and restrict high-risk permissions")
		recommendations = append(recommendations, "Implement least privilege access controls")
	}

	// General recommendations
	recommendations = append(recommendations, "Implement continuous security monitoring")
	recommendations = append(recommendations, "Regular security assessments and penetration testing")
	recommendations = append(recommendations, "Implement automated security scanning")
	recommendations = append(recommendations, "Establish incident response procedures")

	return recommendations
}
