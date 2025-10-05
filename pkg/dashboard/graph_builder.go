package dashboard

import (
	"fmt"
	"log"
	"regexp"
	"strings"
	"time"
)

// GraphBuilder processes command results and builds attack graphs
type GraphBuilder struct {
	storage *Storage
}

// NewGraphBuilder creates a new graph builder
func NewGraphBuilder(storage *Storage) *GraphBuilder {
	return &GraphBuilder{storage: storage}
}

// ProcessCommandResult processes a command result and updates the attack graph
func (gb *GraphBuilder) ProcessCommandResult(cmd *CommandResult, findings []Finding, _ ModuleSummary) error {
	log.Printf("🔍 Processing command result for attack graph: %s", cmd.Command)

	// Extract nodes and edges based on command type and findings
	nodes, edges := gb.extractGraphElements(cmd, findings, ModuleSummary{})

	if len(nodes) == 0 && len(edges) == 0 {
		log.Printf("ℹ️  No graph elements extracted from command: %s", cmd.Command)
		return nil
	}

	// Store the graph delta
	deltaType := "add"
	if cmd.Status == "error" {
		deltaType = "error"
	}

	err := gb.storage.StoreGraphDelta(cmd.ID, deltaType, nodes, edges)
	if err != nil {
		return fmt.Errorf("failed to store graph delta: %w", err)
	}

	// Analyze for new attack chains
	chains, err := gb.analyzeAttackChains(cmd.ID)
	if err != nil {
		log.Printf("⚠️  Failed to analyze attack chains: %v", err)
	}

	// Log findings
	log.Printf("📊 Extracted %d nodes and %d edges from %s", len(nodes), len(edges), cmd.Command)
	if len(chains) > 0 {
		log.Printf("🚨 Found %d potential attack chains", len(chains))
	}

	return nil
}

// extractGraphElements extracts nodes and edges from command results
func (gb *GraphBuilder) extractGraphElements(cmd *CommandResult, findings []Finding, _ ModuleSummary) ([]GraphNode, []GraphEdge) {
	var nodes []GraphNode
	var edges []GraphEdge

	// Extract based on command type
	switch cmd.Module {
	case "recon":
		nodes, edges = gb.extractReconElements(cmd, findings)
	case "rbac":
		nodes, edges = gb.extractRBACElements(cmd, findings)
	case "network":
		nodes, edges = gb.extractNetworkElements(cmd, findings)
	case "secrets":
		nodes, edges = gb.extractSecretsElements(cmd, findings)
	case "workload":
		nodes, edges = gb.extractWorkloadElements(cmd, findings)
	case "cloud":
		nodes, edges = gb.extractCloudElements(cmd, findings)
	default:
		// Generic extraction for unknown modules
		nodes, edges = gb.extractGenericElements(cmd, findings)
	}

	return nodes, edges
}

// extractReconElements extracts nodes and edges from reconnaissance results
func (gb *GraphBuilder) extractReconElements(_ *CommandResult, findings []Finding) ([]GraphNode, []GraphEdge) {
	var nodes []GraphNode
	var edges []GraphEdge

	// Extract pods, services, secrets, etc. from findings
	for _, finding := range findings {
		// Create nodes for resources
		if finding.Resource != "" {
			node := GraphNode{
				ID:   gb.generateNodeID(finding.Type, finding.Resource),
				Type: gb.mapFindingTypeToNodeType(finding.Type),
				Name: finding.Resource,
				Namespace: finding.Namespace,
				Metadata: map[string]interface{}{
					"severity":    finding.Severity,
					"riskScore":   finding.RiskScore,
					"description": finding.Description,
					"remediation": finding.Remediation,
				},
			}
			nodes = append(nodes, node)
		}

		// Create edges for relationships
		if finding.Type == "privilege-escalation" || finding.Type == "rbac-violation" {
			// Extract source and target from description
			source, target := gb.extractRelationshipFromFinding(finding)
			if source != "" && target != "" {
				edge := GraphEdge{
					ID:       gb.generateEdgeID(source, target, finding.Type),
					SourceID: source,
					TargetID: target,
					Type:     gb.mapFindingTypeToEdgeType(finding.Type),
					Weight:   finding.RiskScore,
					Metadata: map[string]interface{}{
						"severity":    finding.Severity,
						"description": finding.Description,
					},
				}
				edges = append(edges, edge)
			}
		}
	}

	return nodes, edges
}

// extractRBACElements extracts RBAC-related nodes and edges
func (gb *GraphBuilder) extractRBACElements(_ *CommandResult, findings []Finding) ([]GraphNode, []GraphEdge) {
	var nodes []GraphNode
	var edges []GraphEdge

	for _, finding := range findings {
		// Create service account nodes
		if strings.Contains(finding.Type, "service-account") {
			node := GraphNode{
				ID:   gb.generateNodeID("service-account", finding.Resource),
				Type: "service-account",
				Name: finding.Resource,
				Namespace: finding.Namespace,
				Metadata: map[string]interface{}{
					"severity": finding.Severity,
					"riskScore": finding.RiskScore,
				},
			}
			nodes = append(nodes, node)
		}

		// Create role nodes
		if strings.Contains(finding.Type, "role") {
			node := GraphNode{
				ID:   gb.generateNodeID("role", finding.Resource),
				Type: "role",
				Name: finding.Resource,
				Namespace: finding.Namespace,
				Metadata: map[string]interface{}{
					"severity": finding.Severity,
					"riskScore": finding.RiskScore,
				},
			}
			nodes = append(nodes, node)
		}

		// Create privilege escalation edges
		if finding.Type == "rbac-escalation" {
			source, target := gb.extractRBACRelationship(finding)
			if source != "" && target != "" {
				edge := GraphEdge{
					ID:       gb.generateEdgeID(source, target, "privilege-escalation"),
					SourceID: source,
					TargetID: target,
					Type:     "privilege-escalation",
					Weight:   finding.RiskScore,
					Metadata: map[string]interface{}{
						"severity": finding.Severity,
						"description": finding.Description,
					},
				}
				edges = append(edges, edge)
			}
		}
	}

	return nodes, edges
}

// extractNetworkElements extracts network-related nodes and edges
func (gb *GraphBuilder) extractNetworkElements(_ *CommandResult, findings []Finding) ([]GraphNode, []GraphEdge) {
	var nodes []GraphNode
	var edges []GraphEdge

	for _, finding := range findings {
		// Create service nodes
		if strings.Contains(finding.Type, "service") {
			node := GraphNode{
				ID:   gb.generateNodeID("service", finding.Resource),
				Type: "service",
				Name: finding.Resource,
				Namespace: finding.Namespace,
				Metadata: map[string]interface{}{
					"severity": finding.Severity,
					"riskScore": finding.RiskScore,
				},
			}
			nodes = append(nodes, node)
		}

		// Create network access edges
		if finding.Type == "network-exposure" {
			source, target := gb.extractNetworkRelationship(finding)
			if source != "" && target != "" {
				edge := GraphEdge{
					ID:       gb.generateEdgeID(source, target, "network"),
					SourceID: source,
					TargetID: target,
					Type:     "network",
					Weight:   finding.RiskScore,
					Metadata: map[string]interface{}{
						"severity": finding.Severity,
						"description": finding.Description,
					},
				}
				edges = append(edges, edge)
			}
		}
	}

	return nodes, edges
}

// extractSecretsElements extracts secrets-related nodes and edges
func (gb *GraphBuilder) extractSecretsElements(_ *CommandResult, findings []Finding) ([]GraphNode, []GraphEdge) {
	var nodes []GraphNode
	var edges []GraphEdge

	for _, finding := range findings {
		// Create secret nodes
		if strings.Contains(finding.Type, "secret") {
			node := GraphNode{
				ID:   gb.generateNodeID("secret", finding.Resource),
				Type: "secret",
				Name: finding.Resource,
				Namespace: finding.Namespace,
				Metadata: map[string]interface{}{
					"severity": finding.Severity,
					"riskScore": finding.RiskScore,
					"sensitive": true,
				},
			}
			nodes = append(nodes, node)
		}

		// Create access edges to secrets
		if finding.Type == "secret-exposure" {
			source, target := gb.extractSecretAccess(finding)
			if source != "" && target != "" {
				edge := GraphEdge{
					ID:       gb.generateEdgeID(source, target, "access"),
					SourceID: source,
					TargetID: target,
					Type:     "access",
					Weight:   finding.RiskScore,
					Metadata: map[string]interface{}{
						"severity": finding.Severity,
						"description": finding.Description,
						"sensitive": true,
					},
				}
				edges = append(edges, edge)
			}
		}
	}

	return nodes, edges
}

// extractWorkloadElements extracts workload-related nodes and edges
func (gb *GraphBuilder) extractWorkloadElements(_ *CommandResult, findings []Finding) ([]GraphNode, []GraphEdge) {
	var nodes []GraphNode
	var edges []GraphEdge

	for _, finding := range findings {
		// Create pod nodes
		if strings.Contains(finding.Type, "pod") {
			node := GraphNode{
				ID:   gb.generateNodeID("pod", finding.Resource),
				Type: "pod",
				Name: finding.Resource,
				Namespace: finding.Namespace,
				Metadata: map[string]interface{}{
					"severity": finding.Severity,
					"riskScore": finding.RiskScore,
					"privileged": strings.Contains(finding.Description, "privileged"),
				},
			}
			nodes = append(nodes, node)
		}

		// Create host access edges
		if finding.Type == "host-access" {
			source, target := gb.extractHostAccess(finding)
			if source != "" && target != "" {
				edge := GraphEdge{
					ID:       gb.generateEdgeID(source, target, "host-access"),
					SourceID: source,
					TargetID: target,
					Type:     "host-access",
					Weight:   finding.RiskScore,
					Metadata: map[string]interface{}{
						"severity": finding.Severity,
						"description": finding.Description,
					},
				}
				edges = append(edges, edge)
			}
		}
	}

	return nodes, edges
}

// extractCloudElements extracts cloud-related nodes and edges
func (gb *GraphBuilder) extractCloudElements(_ *CommandResult, findings []Finding) ([]GraphNode, []GraphEdge) {
	var nodes []GraphNode
	var edges []GraphEdge

	for _, finding := range findings {
		// Create cloud resource nodes
		if strings.Contains(finding.Type, "cloud") {
			node := GraphNode{
				ID:   gb.generateNodeID("cloud-resource", finding.Resource),
				Type: "cloud-resource",
				Name: finding.Resource,
				Metadata: map[string]interface{}{
					"severity": finding.Severity,
					"riskScore": finding.RiskScore,
					"cloudProvider": gb.extractCloudProvider(finding),
				},
			}
			nodes = append(nodes, node)
		}

		// Create cloud permission edges
		if finding.Type == "cloud-permission" {
			source, target := gb.extractCloudPermission(finding)
			if source != "" && target != "" {
				edge := GraphEdge{
					ID:       gb.generateEdgeID(source, target, "cloud-permission"),
					SourceID: source,
					TargetID: target,
					Type:     "cloud-permission",
					Weight:   finding.RiskScore,
					Metadata: map[string]interface{}{
						"severity": finding.Severity,
						"description": finding.Description,
					},
				}
				edges = append(edges, edge)
			}
		}
	}

	return nodes, edges
}

// extractGenericElements extracts generic nodes and edges for unknown modules
func (gb *GraphBuilder) extractGenericElements(cmd *CommandResult, findings []Finding) ([]GraphNode, []GraphEdge) {
	var nodes []GraphNode
	var edges []GraphEdge

	// Create a generic node for the command
	node := GraphNode{
		ID:   gb.generateNodeID("command", cmd.ID),
		Type: "command",
		Name: cmd.Command,
		Metadata: map[string]interface{}{
			"module": cmd.Module,
			"status": cmd.Status,
			"findings": len(findings),
		},
	}
	nodes = append(nodes, node)

	// Create edges for each finding
	for _, finding := range findings {
		if finding.Resource != "" {
			targetNode := GraphNode{
				ID:   gb.generateNodeID("resource", finding.Resource),
				Type: "resource",
				Name: finding.Resource,
				Namespace: finding.Namespace,
				Metadata: map[string]interface{}{
					"severity": finding.Severity,
					"riskScore": finding.RiskScore,
				},
			}
			nodes = append(nodes, targetNode)

			edge := GraphEdge{
				ID:       gb.generateEdgeID(node.ID, targetNode.ID, "discovered"),
				SourceID: node.ID,
				TargetID: targetNode.ID,
				Type:     "discovered",
				Weight:   finding.RiskScore,
				Metadata: map[string]interface{}{
					"severity": finding.Severity,
					"description": finding.Description,
				},
			}
			edges = append(edges, edge)
		}
	}

	return nodes, edges
}

// analyzeAttackChains analyzes the current graph for potential attack chains
func (gb *GraphBuilder) analyzeAttackChains(_ string) ([]AttackChain, error) {
	// Get the full graph
	graph, err := gb.storage.GetFullGraph()
	if err != nil {
		return nil, err
	}

	// Find potential attack chains
	chains := gb.findAttackChains(graph)

	// Filter chains that are new or have changed
	var newChains []AttackChain
	for _, chain := range chains {
		if gb.isNewChain(chain) {
			newChains = append(newChains, chain)
		}
	}

	return newChains, nil
}

// findAttackChains finds potential attack chains in the graph
func (gb *GraphBuilder) findAttackChains(graph *AttackGraph) []AttackChain {
	var chains []AttackChain

	// Find high-risk nodes (potential targets)
	highRiskNodes := gb.getHighRiskNodes(graph)
	
	// Find entry points (pods, services, etc.)
	entryPoints := gb.getEntryPoints(graph)

	// For each entry point, try to find paths to high-risk targets
	for _, entry := range entryPoints {
		for _, target := range highRiskNodes {
			path := gb.findPath(graph, entry.ID, target.ID)
			if len(path) > 1 {
				chain := AttackChain{
					ID:          gb.generateChainID(entry.ID, target.ID),
					Source:      entry.ID,
					Target:      target.ID,
					Path:        path,
					RiskScore:   gb.calculateChainRisk(graph, path),
					Steps:       gb.buildChainSteps(graph, path),
					Confidence:  gb.calculateChainConfidence(graph, path),
					LastUpdated: time.Now(),
				}
				chains = append(chains, chain)
			}
		}
	}

	return chains
}

// Helper methods for graph analysis

func (gb *GraphBuilder) mapFindingTypeToNodeType(findingType string) string {
	switch {
	case strings.Contains(findingType, "pod"):
		return "pod"
	case strings.Contains(findingType, "service"):
		return "service"
	case strings.Contains(findingType, "secret"):
		return "secret"
	case strings.Contains(findingType, "sa") || strings.Contains(findingType, "service-account"):
		return "service-account"
	case strings.Contains(findingType, "role"):
		return "role"
	case strings.Contains(findingType, "user"):
		return "user"
	case strings.Contains(findingType, "namespace"):
		return "namespace"
	default:
		return "resource"
	}
}

func (gb *GraphBuilder) mapFindingTypeToEdgeType(findingType string) string {
	switch {
	case strings.Contains(findingType, "privilege") || strings.Contains(findingType, "escalation"):
		return "privilege-escalation"
	case strings.Contains(findingType, "rbac"):
		return "rbac"
	case strings.Contains(findingType, "network"):
		return "network"
	case strings.Contains(findingType, "access"):
		return "access"
	default:
		return "relationship"
	}
}

func (gb *GraphBuilder) generateNodeID(nodeType, name string) string {
	return fmt.Sprintf("%s-%s", nodeType, strings.ReplaceAll(name, "/", "-"))
}

func (gb *GraphBuilder) generateEdgeID(source, target, edgeType string) string {
	return fmt.Sprintf("%s-%s-%s", source, target, edgeType)
}

func (gb *GraphBuilder) generateChainID(source, target string) string {
	return fmt.Sprintf("chain-%s-%s", source, target)
}

func (gb *GraphBuilder) extractRelationshipFromFinding(finding Finding) (string, string) {
	// Use regex to extract source and target from description
	// This is a simplified implementation
	re := regexp.MustCompile(`(\w+)\s+(?:can|has|allows)\s+(?:access|escalate|to)\s+(\w+)`)
	matches := re.FindStringSubmatch(finding.Description)
	if len(matches) >= 3 {
		return matches[1], matches[2]
	}
	return "", ""
}

func (gb *GraphBuilder) extractRBACRelationship(finding Finding) (string, string) {
	// Extract RBAC relationships
	re := regexp.MustCompile(`(\w+)\s+(?:can|has)\s+(?:escalate|access)\s+to\s+(\w+)`)
	matches := re.FindStringSubmatch(finding.Description)
	if len(matches) >= 3 {
		return matches[1], matches[2]
	}
	return "", ""
}

func (gb *GraphBuilder) extractNetworkRelationship(finding Finding) (string, string) {
	// Extract network relationships
	re := regexp.MustCompile(`(\w+)\s+(?:exposed|accessible)\s+to\s+(\w+)`)
	matches := re.FindStringSubmatch(finding.Description)
	if len(matches) >= 3 {
		return matches[1], matches[2]
	}
	return "", ""
}

func (gb *GraphBuilder) extractSecretAccess(finding Finding) (string, string) {
	// Extract secret access relationships
	re := regexp.MustCompile(`(\w+)\s+(?:can|has)\s+access\s+to\s+secret\s+(\w+)`)
	matches := re.FindStringSubmatch(finding.Description)
	if len(matches) >= 3 {
		return matches[1], matches[2]
	}
	return "", ""
}

func (gb *GraphBuilder) extractHostAccess(finding Finding) (string, string) {
	// Extract host access relationships
	re := regexp.MustCompile(`(\w+)\s+(?:can|has)\s+host\s+access\s+to\s+(\w+)`)
	matches := re.FindStringSubmatch(finding.Description)
	if len(matches) >= 3 {
		return matches[1], matches[2]
	}
	return "", ""
}

func (gb *GraphBuilder) extractCloudProvider(finding Finding) string {
	// Extract cloud provider from description
	if strings.Contains(finding.Description, "AWS") {
		return "aws"
	}
	if strings.Contains(finding.Description, "GCP") {
		return "gcp"
	}
	if strings.Contains(finding.Description, "Azure") {
		return "azure"
	}
	return "unknown"
}

func (gb *GraphBuilder) extractCloudPermission(finding Finding) (string, string) {
	// Extract cloud permission relationships
	re := regexp.MustCompile(`(\w+)\s+(?:can|has)\s+(\w+)\s+permission`)
	matches := re.FindStringSubmatch(finding.Description)
	if len(matches) >= 3 {
		return matches[1], matches[2]
	}
	return "", ""
}

func (gb *GraphBuilder) getHighRiskNodes(graph *AttackGraph) []GraphNode {
	var highRisk []GraphNode
	for _, node := range graph.Nodes {
		if risk, ok := node.Metadata["riskScore"].(float64); ok && risk > 7.0 {
			highRisk = append(highRisk, node)
		}
	}
	return highRisk
}

func (gb *GraphBuilder) getEntryPoints(graph *AttackGraph) []GraphNode {
	var entryPoints []GraphNode
	for _, node := range graph.Nodes {
		if node.Type == "pod" || node.Type == "service" || node.Type == "user" {
			entryPoints = append(entryPoints, node)
		}
	}
	return entryPoints
}

func (gb *GraphBuilder) findPath(graph *AttackGraph, source, target string) []string {
	// Simple BFS pathfinding
	visited := make(map[string]bool)
	queue := [][]string{{source}}
	
	for len(queue) > 0 {
		path := queue[0]
		queue = queue[1:]
		
		current := path[len(path)-1]
		if current == target {
			return path
		}
		
		if visited[current] {
			continue
		}
		visited[current] = true
		
		// Find edges from current node
		for _, edge := range graph.Edges {
			if edge.SourceID == current && !visited[edge.TargetID] {
				newPath := append(path, edge.TargetID)
				queue = append(queue, newPath)
			}
		}
	}
	
	return nil
}

func (gb *GraphBuilder) calculateChainRisk(graph *AttackGraph, path []string) float64 {
	if len(path) < 2 {
		return 0.0
	}
	
	totalRisk := 0.0
	for i := 0; i < len(path)-1; i++ {
		// Find edge between path[i] and path[i+1]
		for _, edge := range graph.Edges {
			if edge.SourceID == path[i] && edge.TargetID == path[i+1] {
				totalRisk += edge.Weight
				break
			}
		}
	}
	
	return totalRisk / float64(len(path)-1)
}

func (gb *GraphBuilder) buildChainSteps(graph *AttackGraph, path []string) []ChainStep {
	var steps []ChainStep
	
	for i := 0; i < len(path)-1; i++ {
		// Find edge between path[i] and path[i+1]
		for _, edge := range graph.Edges {
			if edge.SourceID == path[i] && edge.TargetID == path[i+1] {
				step := ChainStep{
					From:        path[i],
					To:          path[i+1],
					Action:      edge.Type,
					Privilege:   edge.Type,
					Requirement: fmt.Sprintf("Access to %s", path[i]),
					Risk:        edge.Weight,
					Metadata:    edge.Metadata,
				}
				steps = append(steps, step)
				break
			}
		}
	}
	
	return steps
}

func (gb *GraphBuilder) calculateChainConfidence(graph *AttackGraph, path []string) float64 {
	// Simple confidence calculation based on path length and edge weights
	if len(path) < 2 {
		return 0.0
	}
	
	confidence := 1.0
	for i := 0; i < len(path)-1; i++ {
		// Find edge between path[i] and path[i+1]
		for _, edge := range graph.Edges {
			if edge.SourceID == path[i] && edge.TargetID == path[i+1] {
				// Reduce confidence for longer paths and lower weights
				confidence *= (edge.Weight / 10.0)
				break
			}
		}
	}
	
	return confidence
}

func (gb *GraphBuilder) isNewChain(chain AttackChain) bool {
	// Simple check - in a real implementation, this would check against stored chains
	return chain.RiskScore > 5.0
}
