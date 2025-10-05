package recon_graph

import (
	"time"
)

// NodeType represents the type of a node in the recon graph
type NodeType string

const (
	// Identity nodes
	NodeTypeServiceAccount NodeType = "serviceaccount"
	NodeTypeUser           NodeType = "user"
	NodeTypeGroup          NodeType = "group"
	NodeTypeCloudIdentity  NodeType = "cloudidentity"

	// Resource nodes
	NodeTypePod         NodeType = "pod"
	NodeTypeDeployment  NodeType = "deployment"
	NodeTypeService     NodeType = "service"
	NodeTypeConfigMap   NodeType = "configmap"
	NodeTypeSecret      NodeType = "secret"
	NodeTypeRole        NodeType = "role"
	NodeTypeClusterRole NodeType = "clusterrole"
	NodeTypeNamespace   NodeType = "namespace"
	NodeTypeNode        NodeType = "node"

	// Network nodes
	NodeTypeEndpoint      NodeType = "endpoint"
	NodeTypeLoadBalancer  NodeType = "loadbalancer"
	NodeTypeIngress       NodeType = "ingress"
	NodeTypeNetworkPolicy NodeType = "networkpolicy"

	// Cloud nodes
	NodeTypeCloudResource NodeType = "cloudresource"
	NodeTypeCloudService  NodeType = "cloudservice"
	NodeTypeCloudRole     NodeType = "cloudrole"
	NodeTypeCloudUser     NodeType = "clouduser"
)

// EdgeType represents the type of relationship between nodes
type EdgeType string

const (
	// Permission edges
	EdgeTypeCanAccess   EdgeType = "can_access"
	EdgeTypeCanCreate   EdgeType = "can_create"
	EdgeTypeCanDelete   EdgeType = "can_delete"
	EdgeTypeCanUpdate   EdgeType = "can_update"
	EdgeTypeCanList     EdgeType = "can_list"
	EdgeTypeCanWatch    EdgeType = "can_watch"
	EdgeTypeCanExecute  EdgeType = "can_execute"
	EdgeTypeCanBind     EdgeType = "can_bind"
	EdgeTypeCanEscalate EdgeType = "can_escalate"

	// Network edges
	EdgeTypeCanConnect EdgeType = "can_connect"
	EdgeTypeCanReach   EdgeType = "can_reach"
	EdgeTypeCanExpose  EdgeType = "can_expose"
	EdgeTypeCanRoute   EdgeType = "can_route"

	// Cloud edges
	EdgeTypeCanAssume      EdgeType = "can_assume"
	EdgeTypeCanAccessCloud EdgeType = "can_access_cloud"
	EdgeTypeCanCreateCloud EdgeType = "can_create_cloud"
	EdgeTypeCanDeleteCloud EdgeType = "can_delete_cloud"

	// Ownership edges
	EdgeTypeOwns      EdgeType = "owns"
	EdgeTypeContains  EdgeType = "contains"
	EdgeTypeDependsOn EdgeType = "depends_on"
	EdgeTypeRunsOn    EdgeType = "runs_on"
	EdgeTypeMountedOn EdgeType = "mounted_on"
)

// Node represents a node in the recon graph
type Node struct {
	ID              string                 `json:"id"`
	Type            NodeType               `json:"type"`
	Name            string                 `json:"name"`
	Namespace       string                 `json:"namespace"`
	Cluster         string                 `json:"cluster"`
	Cloud           string                 `json:"cloud,omitempty"`
	Properties      map[string]interface{} `json:"properties"`
	Vulnerabilities []Vulnerability        `json:"vulnerabilities,omitempty"`
	RiskScore       float64                `json:"riskScore"`
	Metadata        map[string]string      `json:"metadata"`
	CreatedAt       time.Time              `json:"createdAt"`
	UpdatedAt       time.Time              `json:"updatedAt"`
}

// Edge represents an edge in the recon graph
type Edge struct {
	ID         string                 `json:"id"`
	Source     string                 `json:"source"`
	Target     string                 `json:"target"`
	Type       EdgeType               `json:"type"`
	Weight     float64                `json:"weight"`
	Properties map[string]interface{} `json:"properties"`
	RiskScore  float64                `json:"riskScore"`
	Metadata   map[string]string      `json:"metadata"`
	CreatedAt  time.Time              `json:"createdAt"`
	UpdatedAt  time.Time              `json:"updatedAt"`
}

// Vulnerability represents a vulnerability in the recon graph
type Vulnerability struct {
	ID          string            `json:"id"`
	Type        string            `json:"type"`
	Severity    string            `json:"severity"`
	Title       string            `json:"title"`
	Description string            `json:"description"`
	CVSS        float64           `json:"cvss"`
	Exploitable bool              `json:"exploitable"`
	Remediation string            `json:"remediation"`
	Metadata    map[string]string `json:"metadata"`
}

// AttackChain represents a potential attack chain
type AttackChain struct {
	ID          string            `json:"id"`
	Path        []string          `json:"path"`  // Node IDs in the chain
	Edges       []string          `json:"edges"` // Edge IDs in the chain
	RiskScore   float64           `json:"riskScore"`
	Severity    string            `json:"severity"`
	Description string            `json:"description"`
	Steps       []AttackStep      `json:"steps"`
	Metadata    map[string]string `json:"metadata"`
	CreatedAt   time.Time         `json:"createdAt"`
}

// AttackStep represents a step in an attack chain
type AttackStep struct {
	Step        int               `json:"step"`
	NodeID      string            `json:"nodeId"`
	EdgeID      string            `json:"edgeId,omitempty"`
	Action      string            `json:"action"`
	Description string            `json:"description"`
	RiskScore   float64           `json:"riskScore"`
	Metadata    map[string]string `json:"metadata"`
}

// ReconGraph represents the complete recon graph
type ReconGraph struct {
	Nodes        map[string]*Node       `json:"nodes"`
	Edges        map[string]*Edge       `json:"edges"`
	AttackChains []AttackChain          `json:"attackChains"`
	Metadata     map[string]interface{} `json:"metadata"`
	CreatedAt    time.Time              `json:"createdAt"`
	UpdatedAt    time.Time              `json:"updatedAt"`
}

// GraphAnalyzer represents the graph analysis engine
type GraphAnalyzer struct {
	graph *ReconGraph
}

// NewReconGraph creates a new recon graph
func NewReconGraph() *ReconGraph {
	return &ReconGraph{
		Nodes:        make(map[string]*Node),
		Edges:        make(map[string]*Edge),
		AttackChains: []AttackChain{},
		Metadata:     make(map[string]interface{}),
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
}

// NewGraphAnalyzer creates a new graph analyzer
func NewGraphAnalyzer(graph *ReconGraph) *GraphAnalyzer {
	return &GraphAnalyzer{
		graph: graph,
	}
}

// AddNode adds a node to the graph
func (rg *ReconGraph) AddNode(node *Node) {
	node.CreatedAt = time.Now()
	node.UpdatedAt = time.Now()
	rg.Nodes[node.ID] = node
	rg.UpdatedAt = time.Now()
}

// AddEdge adds an edge to the graph
func (rg *ReconGraph) AddEdge(edge *Edge) {
	edge.CreatedAt = time.Now()
	edge.UpdatedAt = time.Now()
	rg.Edges[edge.ID] = edge
	rg.UpdatedAt = time.Now()
}

// GetNode retrieves a node by ID
func (rg *ReconGraph) GetNode(id string) (*Node, bool) {
	node, exists := rg.Nodes[id]
	return node, exists
}

// GetEdge retrieves an edge by ID
func (rg *ReconGraph) GetEdge(id string) (*Edge, bool) {
	edge, exists := rg.Edges[id]
	return edge, exists
}

// GetNeighbors returns all neighbors of a node
func (rg *ReconGraph) GetNeighbors(nodeID string) []*Node {
	var neighbors []*Node
	for _, edge := range rg.Edges {
		if edge.Source == nodeID {
			if target, exists := rg.Nodes[edge.Target]; exists {
				neighbors = append(neighbors, target)
			}
		} else if edge.Target == nodeID {
			if source, exists := rg.Nodes[edge.Source]; exists {
				neighbors = append(neighbors, source)
			}
		}
	}
	return neighbors
}

// GetEdgesFrom returns all edges from a node
func (rg *ReconGraph) GetEdgesFrom(nodeID string) []*Edge {
	var edges []*Edge
	for _, edge := range rg.Edges {
		if edge.Source == nodeID {
			edges = append(edges, edge)
		}
	}
	return edges
}

// GetEdgesTo returns all edges to a node
func (rg *ReconGraph) GetEdgesTo(nodeID string) []*Edge {
	var edges []*Edge
	for _, edge := range rg.Edges {
		if edge.Target == nodeID {
			edges = append(edges, edge)
		}
	}
	return edges
}

// GetNodesByType returns all nodes of a specific type
func (rg *ReconGraph) GetNodesByType(nodeType NodeType) []*Node {
	var nodes []*Node
	for _, node := range rg.Nodes {
		if node.Type == nodeType {
			nodes = append(nodes, node)
		}
	}
	return nodes
}

// GetEdgesByType returns all edges of a specific type
func (rg *ReconGraph) GetEdgesByType(edgeType EdgeType) []*Edge {
	var edges []*Edge
	for _, edge := range rg.Edges {
		if edge.Type == edgeType {
			edges = append(edges, edge)
		}
	}
	return edges
}

// GetHighRiskNodes returns all nodes with high risk scores
func (rg *ReconGraph) GetHighRiskNodes(threshold float64) []*Node {
	var nodes []*Node
	for _, node := range rg.Nodes {
		if node.RiskScore >= threshold {
			nodes = append(nodes, node)
		}
	}
	return nodes
}

// GetHighRiskEdges returns all edges with high risk scores
func (rg *ReconGraph) GetHighRiskEdges(threshold float64) []*Edge {
	var edges []*Edge
	for _, edge := range rg.Edges {
		if edge.RiskScore >= threshold {
			edges = append(edges, edge)
		}
	}
	return edges
}

// AddAttackChain adds an attack chain to the graph
func (rg *ReconGraph) AddAttackChain(chain AttackChain) {
	chain.CreatedAt = time.Now()
	rg.AttackChains = append(rg.AttackChains, chain)
	rg.UpdatedAt = time.Now()
}

// GetAttackChains returns all attack chains
func (rg *ReconGraph) GetAttackChains() []AttackChain {
	return rg.AttackChains
}

// GetAttackChainsBySeverity returns attack chains filtered by severity
func (rg *ReconGraph) GetAttackChainsBySeverity(severity string) []AttackChain {
	var chains []AttackChain
	for _, chain := range rg.AttackChains {
		if chain.Severity == severity {
			chains = append(chains, chain)
		}
	}
	return chains
}

// GetAttackChainsByRiskScore returns attack chains filtered by risk score
func (rg *ReconGraph) GetAttackChainsByRiskScore(threshold float64) []AttackChain {
	var chains []AttackChain
	for _, chain := range rg.AttackChains {
		if chain.RiskScore >= threshold {
			chains = append(chains, chain)
		}
	}
	return chains
}

// GetGraphStats returns statistics about the graph
func (rg *ReconGraph) GetGraphStats() map[string]interface{} {
	stats := make(map[string]interface{})

	// Node statistics
	stats["totalNodes"] = len(rg.Nodes)
	nodeTypeCounts := make(map[NodeType]int)
	for _, node := range rg.Nodes {
		nodeTypeCounts[node.Type]++
	}
	stats["nodeTypes"] = nodeTypeCounts

	// Edge statistics
	stats["totalEdges"] = len(rg.Edges)
	edgeTypeCounts := make(map[EdgeType]int)
	for _, edge := range rg.Edges {
		edgeTypeCounts[edge.Type]++
	}
	stats["edgeTypes"] = edgeTypeCounts

	// Attack chain statistics
	stats["totalAttackChains"] = len(rg.AttackChains)
	severityCounts := make(map[string]int)
	for _, chain := range rg.AttackChains {
		severityCounts[chain.Severity]++
	}
	stats["attackChainSeverities"] = severityCounts

	// Risk statistics
	highRiskNodes := rg.GetHighRiskNodes(7.0)
	highRiskEdges := rg.GetHighRiskEdges(7.0)
	stats["highRiskNodes"] = len(highRiskNodes)
	stats["highRiskEdges"] = len(highRiskEdges)

	return stats
}
