package recon_graph

import (
	"fmt"
	"math"
	"sort"
	"time"
)

// ChainingEngine represents the attack chain analysis engine
type ChainingEngine struct {
	graph *ReconGraph
}

// NewChainingEngine creates a new chaining engine
func NewChainingEngine(graph *ReconGraph) *ChainingEngine {
	return &ChainingEngine{
		graph: graph,
	}
}

// FindAttackChains finds all possible attack chains in the graph
func (ce *ChainingEngine) FindAttackChains() []AttackChain {
	var chains []AttackChain

	// Find chains from high-risk nodes
	highRiskNodes := ce.graph.GetHighRiskNodes(7.0)
	for _, startNode := range highRiskNodes {
		chains = append(chains, ce.findChainsFromNode(startNode)...)
	}

	// Find chains from service accounts with high privileges
	serviceAccounts := ce.graph.GetNodesByType(NodeTypeServiceAccount)
	for _, sa := range serviceAccounts {
		if sa.RiskScore >= 6.0 {
			chains = append(chains, ce.findChainsFromNode(sa)...)
		}
	}

	// Find chains from exposed endpoints
	endpoints := ce.graph.GetNodesByType(NodeTypeEndpoint)
	for _, endpoint := range endpoints {
		if ce.isExposed(endpoint) {
			chains = append(chains, ce.findChainsFromNode(endpoint)...)
		}
	}

	// Remove duplicate chains and sort by risk score
	chains = ce.deduplicateChains(chains)
	sort.Slice(chains, func(i, j int) bool {
		return chains[i].RiskScore > chains[j].RiskScore
	})

	return chains
}

// findChainsFromNode finds attack chains starting from a specific node
func (ce *ChainingEngine) findChainsFromNode(startNode *Node) []AttackChain {
	var chains []AttackChain

	// Use BFS to find all possible paths
	visited := make(map[string]bool)
	queue := []PathNode{{Node: startNode, Path: []string{startNode.ID}, RiskScore: startNode.RiskScore}}

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		if visited[current.Node.ID] {
			continue
		}
		visited[current.Node.ID] = true

		// Check if this is a high-value target
		if ce.isHighValueTarget(current.Node) {
			chain := ce.createAttackChain(current)
			if chain.RiskScore >= 5.0 {
				chains = append(chains, chain)
			}
		}

		// Continue exploring if path is still viable
		if len(current.Path) < 5 && current.RiskScore >= 3.0 {
			neighbors := ce.graph.GetNeighbors(current.Node.ID)
			for _, neighbor := range neighbors {
				if !visited[neighbor.ID] {
					edge := ce.getEdgeBetween(current.Node.ID, neighbor.ID)
					if edge != nil {
						newPath := append(current.Path, neighbor.ID)
						newRiskScore := current.RiskScore + edge.RiskScore
						queue = append(queue, PathNode{
							Node:      neighbor,
							Path:      newPath,
							RiskScore: newRiskScore,
						})
					}
				}
			}
		}
	}

	return chains
}

// PathNode represents a node in the path exploration
type PathNode struct {
	Node      *Node
	Path      []string
	RiskScore float64
}

// createAttackChain creates an attack chain from a path
func (ce *ChainingEngine) createAttackChain(pathNode PathNode) AttackChain {
	chain := AttackChain{
		ID:          fmt.Sprintf("chain-%d", time.Now().UnixNano()),
		Path:        pathNode.Path,
		RiskScore:   pathNode.RiskScore,
		Severity:    ce.calculateSeverity(pathNode.RiskScore),
		Description: ce.generateChainDescription(pathNode),
		Steps:       ce.generateAttackSteps(pathNode),
		Metadata:    make(map[string]string),
		CreatedAt:   time.Now(),
	}

	return chain
}

// generateAttackSteps generates the steps for an attack chain
func (ce *ChainingEngine) generateAttackSteps(pathNode PathNode) []AttackStep {
	var steps []AttackStep

	for i := 0; i < len(pathNode.Path)-1; i++ {
		currentNodeID := pathNode.Path[i]
		nextNodeID := pathNode.Path[i+1]

		currentNode := ce.graph.Nodes[currentNodeID]
		nextNode := ce.graph.Nodes[nextNodeID]
		edge := ce.getEdgeBetween(currentNodeID, nextNodeID)

		if currentNode != nil && nextNode != nil && edge != nil {
			step := AttackStep{
				Step:        i + 1,
				NodeID:      nextNodeID,
				EdgeID:      edge.ID,
				Action:      ce.getActionFromEdge(edge),
				Description: ce.generateStepDescription(currentNode, nextNode, edge),
				RiskScore:   edge.RiskScore,
				Metadata:    make(map[string]string),
			}
			steps = append(steps, step)
		}
	}

	return steps
}

// getEdgeBetween finds the edge between two nodes
func (ce *ChainingEngine) getEdgeBetween(sourceID, targetID string) *Edge {
	for _, edge := range ce.graph.Edges {
		if edge.Source == sourceID && edge.Target == targetID {
			return edge
		}
		if edge.Target == sourceID && edge.Source == targetID {
			return edge
		}
	}
	return nil
}

// getActionFromEdge determines the action from an edge type
func (ce *ChainingEngine) getActionFromEdge(edge *Edge) string {
	switch edge.Type {
	case EdgeTypeCanAccess:
		return "Access"
	case EdgeTypeCanCreate:
		return "Create"
	case EdgeTypeCanDelete:
		return "Delete"
	case EdgeTypeCanUpdate:
		return "Update"
	case EdgeTypeCanExecute:
		return "Execute"
	case EdgeTypeCanBind:
		return "Bind"
	case EdgeTypeCanEscalate:
		return "Escalate"
	case EdgeTypeCanConnect:
		return "Connect"
	case EdgeTypeCanReach:
		return "Reach"
	case EdgeTypeCanAssume:
		return "Assume"
	default:
		return "Access"
	}
}

// generateStepDescription generates a description for an attack step
func (ce *ChainingEngine) generateStepDescription(source, target *Node, edge *Edge) string {
	return fmt.Sprintf("From %s (%s) to %s (%s) via %s",
		source.Name, source.Type, target.Name, target.Type, edge.Type)
}

// generateChainDescription generates a description for an attack chain
func (ce *ChainingEngine) generateChainDescription(pathNode PathNode) string {
	if len(pathNode.Path) == 0 {
		return "Empty attack chain"
	}

	startNode := ce.graph.Nodes[pathNode.Path[0]]
	endNode := ce.graph.Nodes[pathNode.Path[len(pathNode.Path)-1]]

	if startNode == nil || endNode == nil {
		return "Invalid attack chain"
	}

	return fmt.Sprintf("Attack chain from %s (%s) to %s (%s) with %d steps",
		startNode.Name, startNode.Type, endNode.Name, endNode.Type, len(pathNode.Path))
}

// calculateSeverity calculates the severity based on risk score
func (ce *ChainingEngine) calculateSeverity(riskScore float64) string {
	if riskScore >= 9.0 {
		return "critical"
	} else if riskScore >= 7.0 {
		return "high"
	} else if riskScore >= 5.0 {
		return "medium"
	} else {
		return "low"
	}
}

// isHighValueTarget checks if a node is a high-value target
func (ce *ChainingEngine) isHighValueTarget(node *Node) bool {
	// Check for high-value node types
	highValueTypes := map[NodeType]bool{
		NodeTypeSecret:       true,
		NodeTypeConfigMap:    true,
		NodeTypeClusterRole:  true,
		NodeTypeCloudRole:    true,
		NodeTypeCloudUser:    true,
		NodeTypeLoadBalancer: true,
		NodeTypeIngress:      true,
	}

	if highValueTypes[node.Type] {
		return true
	}

	// Check for high risk score
	if node.RiskScore >= 8.0 {
		return true
	}

	// Check for vulnerabilities
	if len(node.Vulnerabilities) > 0 {
		for _, vuln := range node.Vulnerabilities {
			if vuln.Severity == "critical" || vuln.Severity == "high" {
				return true
			}
		}
	}

	return false
}

// isExposed checks if a node is exposed to external access
func (ce *ChainingEngine) isExposed(node *Node) bool {
	// Check for exposed endpoints
	if node.Type == NodeTypeEndpoint {
		if exposed, ok := node.Properties["exposed"].(bool); ok && exposed {
			return true
		}
	}

	// Check for load balancers
	if node.Type == NodeTypeLoadBalancer {
		return true
	}

	// Check for ingress with external access
	if node.Type == NodeTypeIngress {
		if external, ok := node.Properties["external"].(bool); ok && external {
			return true
		}
	}

	return false
}

// deduplicateChains removes duplicate attack chains
func (ce *ChainingEngine) deduplicateChains(chains []AttackChain) []AttackChain {
	seen := make(map[string]bool)
	var unique []AttackChain

	for _, chain := range chains {
		key := ce.getChainKey(chain)
		if !seen[key] {
			seen[key] = true
			unique = append(unique, chain)
		}
	}

	return unique
}

// getChainKey generates a unique key for a chain
func (ce *ChainingEngine) getChainKey(chain AttackChain) string {
	// Create a key based on the path
	key := ""
	for _, nodeID := range chain.Path {
		key += nodeID + "-"
	}
	return key
}

// FindShortestPath finds the shortest path between two nodes
func (ce *ChainingEngine) FindShortestPath(sourceID, targetID string) []string {
	distances := make(map[string]float64)
	previous := make(map[string]string)
	visited := make(map[string]bool)

	// Initialize distances
	for nodeID := range ce.graph.Nodes {
		distances[nodeID] = math.Inf(1)
	}
	distances[sourceID] = 0

	// Dijkstra's algorithm
	for len(visited) < len(ce.graph.Nodes) {
		// Find unvisited node with minimum distance
		minNode := ""
		minDist := math.Inf(1)
		for nodeID, dist := range distances {
			if !visited[nodeID] && dist < minDist {
				minNode = nodeID
				minDist = dist
			}
		}

		if minNode == "" {
			break
		}

		visited[minNode] = true

		// Update distances to neighbors
		neighbors := ce.graph.GetNeighbors(minNode)
		for _, neighbor := range neighbors {
			edge := ce.getEdgeBetween(minNode, neighbor.ID)
			if edge != nil {
				newDist := distances[minNode] + edge.Weight
				if newDist < distances[neighbor.ID] {
					distances[neighbor.ID] = newDist
					previous[neighbor.ID] = minNode
				}
			}
		}
	}

	// Reconstruct path
	if distances[targetID] == math.Inf(1) {
		return nil
	}

	var path []string
	current := targetID
	for current != "" {
		path = append([]string{current}, path...)
		current = previous[current]
	}

	return path
}

// FindCriticalPaths finds critical paths in the graph
func (ce *ChainingEngine) FindCriticalPaths() []AttackChain {
	var criticalPaths []AttackChain

	// Find paths from high-risk sources to high-value targets
	highRiskSources := ce.graph.GetHighRiskNodes(7.0)
	highValueTargets := ce.findHighValueTargets()

	for _, source := range highRiskSources {
		for _, target := range highValueTargets {
			path := ce.FindShortestPath(source.ID, target.ID)
			if len(path) > 1 {
				chain := ce.createChainFromPath(path)
				if chain.RiskScore >= 6.0 {
					criticalPaths = append(criticalPaths, chain)
				}
			}
		}
	}

	return criticalPaths
}

// findHighValueTargets finds all high-value targets in the graph
func (ce *ChainingEngine) findHighValueTargets() []*Node {
	var targets []*Node

	for _, node := range ce.graph.Nodes {
		if ce.isHighValueTarget(node) {
			targets = append(targets, node)
		}
	}

	return targets
}

// createChainFromPath creates an attack chain from a path
func (ce *ChainingEngine) createChainFromPath(path []string) AttackChain {
	var edges []string
	var steps []AttackStep
	totalRiskScore := 0.0

	for i := 0; i < len(path)-1; i++ {
		edge := ce.getEdgeBetween(path[i], path[i+1])
		if edge != nil {
			edges = append(edges, edge.ID)
			totalRiskScore += edge.RiskScore

			step := AttackStep{
				Step:        i + 1,
				NodeID:      path[i+1],
				EdgeID:      edge.ID,
				Action:      ce.getActionFromEdge(edge),
				Description: ce.generateStepDescription(ce.graph.Nodes[path[i]], ce.graph.Nodes[path[i+1]], edge),
				RiskScore:   edge.RiskScore,
				Metadata:    make(map[string]string),
			}
			steps = append(steps, step)
		}
	}

	return AttackChain{
		ID:          fmt.Sprintf("chain-%d", time.Now().UnixNano()),
		Path:        path,
		Edges:       edges,
		RiskScore:   totalRiskScore,
		Severity:    ce.calculateSeverity(totalRiskScore),
		Description: ce.generateChainDescription(PathNode{Path: path, RiskScore: totalRiskScore}),
		Steps:       steps,
		Metadata:    make(map[string]string),
		CreatedAt:   time.Now(),
	}
}
