package recon_graph

import (
	"fmt"
	"time"
)

// OWASPIntegration represents the integration with OWASP modules
type OWASPIntegration struct {
	graph *ReconGraph
}

// NewOWASPIntegration creates a new OWASP integration
func NewOWASPIntegration(graph *ReconGraph) *OWASPIntegration {
	return &OWASPIntegration{
		graph: graph,
	}
}

// IntegrateK01WorkloadConfigs integrates K01 findings into the graph
func (oi *OWASPIntegration) IntegrateK01WorkloadConfigs(findings []interface{}) error {
	for _, finding := range findings {
		// Convert finding to node
		node := oi.convertWorkloadFindingToNode(finding)
		if node != nil {
			oi.graph.AddNode(node)

			// Add edges for workload relationships
			oi.addWorkloadEdges(node)
		}
	}
	return nil
}

// IntegrateK02SupplyChain integrates K02 findings into the graph
func (oi *OWASPIntegration) IntegrateK02SupplyChain(findings []interface{}) error {
	for _, finding := range findings {
		// Convert finding to node
		node := oi.convertSupplyChainFindingToNode(finding)
		if node != nil {
			oi.graph.AddNode(node)

			// Add edges for supply chain relationships
			oi.addSupplyChainEdges(node)
		}
	}
	return nil
}

// IntegrateK03RBAC integrates K03 findings into the graph
func (oi *OWASPIntegration) IntegrateK03RBAC(findings []interface{}) error {
	for _, finding := range findings {
		// Convert finding to nodes and edges
		nodes, edges := oi.convertRBACFindingToGraph(finding)

		// Add nodes
		for _, node := range nodes {
			oi.graph.AddNode(node)
		}

		// Add edges
		for _, edge := range edges {
			oi.graph.AddEdge(edge)
		}
	}
	return nil
}

// IntegrateK04Policy integrates K04 findings into the graph
func (oi *OWASPIntegration) IntegrateK04Policy(findings []interface{}) error {
	for _, finding := range findings {
		// Convert finding to node
		node := oi.convertPolicyFindingToNode(finding)
		if node != nil {
			oi.graph.AddNode(node)

			// Add edges for policy relationships
			oi.addPolicyEdges(node)
		}
	}
	return nil
}

// IntegrateK05Telemetry integrates K05 findings into the graph
func (oi *OWASPIntegration) IntegrateK05Telemetry(findings []interface{}) error {
	for _, finding := range findings {
		// Convert finding to node
		node := oi.convertTelemetryFindingToNode(finding)
		if node != nil {
			oi.graph.AddNode(node)

			// Add edges for telemetry relationships
			oi.addTelemetryEdges(node)
		}
	}
	return nil
}

// IntegrateK06Auth integrates K06 findings into the graph
func (oi *OWASPIntegration) IntegrateK06Auth(findings []interface{}) error {
	for _, finding := range findings {
		// Convert finding to nodes and edges
		nodes, edges := oi.convertAuthFindingToGraph(finding)

		// Add nodes
		for _, node := range nodes {
			oi.graph.AddNode(node)
		}

		// Add edges
		for _, edge := range edges {
			oi.graph.AddEdge(edge)
		}
	}
	return nil
}

// IntegrateK07Network integrates K07 findings into the graph
func (oi *OWASPIntegration) IntegrateK07Network(findings []interface{}) error {
	for _, finding := range findings {
		// Convert finding to nodes and edges
		nodes, edges := oi.convertNetworkFindingToGraph(finding)

		// Add nodes
		for _, node := range nodes {
			oi.graph.AddNode(node)
		}

		// Add edges
		for _, edge := range edges {
			oi.graph.AddEdge(edge)
		}
	}
	return nil
}

// IntegrateK08Secrets integrates K08 findings into the graph
func (oi *OWASPIntegration) IntegrateK08Secrets(findings []interface{}) error {
	for _, finding := range findings {
		// Convert finding to node
		node := oi.convertSecretFindingToNode(finding)
		if node != nil {
			oi.graph.AddNode(node)

			// Add edges for secret relationships
			oi.addSecretEdges(node)
		}
	}
	return nil
}

// IntegrateK09Components integrates K09 findings into the graph
func (oi *OWASPIntegration) IntegrateK09Components(findings []interface{}) error {
	for _, finding := range findings {
		// Convert finding to node
		node := oi.convertComponentFindingToNode(finding)
		if node != nil {
			oi.graph.AddNode(node)

			// Add edges for component relationships
			oi.addComponentEdges(node)
		}
	}
	return nil
}

// IntegrateK10Vulnerabilities integrates K10 findings into the graph
func (oi *OWASPIntegration) IntegrateK10Vulnerabilities(findings []interface{}) error {
	for _, finding := range findings {
		// Convert finding to node
		node := oi.convertVulnerabilityFindingToNode(finding)
		if node != nil {
			oi.graph.AddNode(node)

			// Add edges for vulnerability relationships
			oi.addVulnerabilityEdges(node)
		}
	}
	return nil
}

// Helper methods for converting findings to graph elements

func (oi *OWASPIntegration) convertWorkloadFindingToNode(finding interface{}) *Node {
	// Extract finding data (this would be more sophisticated in practice)
	findingMap, ok := finding.(map[string]interface{})
	if !ok {
		return nil
	}

	node := &Node{
		ID:         fmt.Sprintf("workload-%d", time.Now().UnixNano()),
		Type:       NodeTypePod,
		Name:       oi.getString(findingMap, "name", "unknown"),
		Namespace:  oi.getString(findingMap, "namespace", "default"),
		Properties: make(map[string]interface{}),
		RiskScore:  oi.getFloat64(findingMap, "riskScore", 5.0),
		Metadata:   make(map[string]string),
	}

	// Add vulnerabilities if present
	if vulns, ok := findingMap["vulnerabilities"].([]interface{}); ok {
		for _, vuln := range vulns {
			if vulnMap, ok := vuln.(map[string]interface{}); ok {
				vulnerability := Vulnerability{
					ID:          oi.getString(vulnMap, "id", ""),
					Type:        oi.getString(vulnMap, "type", ""),
					Severity:    oi.getString(vulnMap, "severity", "medium"),
					Title:       oi.getString(vulnMap, "title", ""),
					Description: oi.getString(vulnMap, "description", ""),
					CVSS:        oi.getFloat64(vulnMap, "cvss", 5.0),
					Exploitable: oi.getBool(vulnMap, "exploitable", false),
					Remediation: oi.getString(vulnMap, "remediation", ""),
					Metadata:    make(map[string]string),
				}
				node.Vulnerabilities = append(node.Vulnerabilities, vulnerability)
			}
		}
	}

	return node
}

func (oi *OWASPIntegration) convertSupplyChainFindingToNode(finding interface{}) *Node {
	findingMap, ok := finding.(map[string]interface{})
	if !ok {
		return nil
	}

	node := &Node{
		ID:         fmt.Sprintf("supplychain-%d", time.Now().UnixNano()),
		Type:       NodeTypePod,
		Name:       oi.getString(findingMap, "name", "unknown"),
		Namespace:  oi.getString(findingMap, "namespace", "default"),
		Properties: make(map[string]interface{}),
		RiskScore:  oi.getFloat64(findingMap, "riskScore", 5.0),
		Metadata:   make(map[string]string),
	}

	return node
}

func (oi *OWASPIntegration) convertRBACFindingToGraph(finding interface{}) ([]*Node, []*Edge) {
	var nodes []*Node
	var edges []*Edge

	findingMap, ok := finding.(map[string]interface{})
	if !ok {
		return nodes, edges
	}

	// Create service account node
	saNode := &Node{
		ID:         fmt.Sprintf("sa-%d", time.Now().UnixNano()),
		Type:       NodeTypeServiceAccount,
		Name:       oi.getString(findingMap, "serviceAccount", "unknown"),
		Namespace:  oi.getString(findingMap, "namespace", "default"),
		Properties: make(map[string]interface{}),
		RiskScore:  oi.getFloat64(findingMap, "riskScore", 5.0),
		Metadata:   make(map[string]string),
	}
	nodes = append(nodes, saNode)

	// Create role node
	roleNode := &Node{
		ID:         fmt.Sprintf("role-%d", time.Now().UnixNano()),
		Type:       NodeTypeRole,
		Name:       oi.getString(findingMap, "role", "unknown"),
		Namespace:  oi.getString(findingMap, "namespace", "default"),
		Properties: make(map[string]interface{}),
		RiskScore:  oi.getFloat64(findingMap, "riskScore", 5.0),
		Metadata:   make(map[string]string),
	}
	nodes = append(nodes, roleNode)

	// Create edge between service account and role
	edge := &Edge{
		ID:         fmt.Sprintf("edge-%d", time.Now().UnixNano()),
		Source:     saNode.ID,
		Target:     roleNode.ID,
		Type:       EdgeTypeCanBind,
		Weight:     1.0,
		Properties: make(map[string]interface{}),
		RiskScore:  oi.getFloat64(findingMap, "riskScore", 5.0),
		Metadata:   make(map[string]string),
	}
	edges = append(edges, edge)

	return nodes, edges
}

func (oi *OWASPIntegration) convertPolicyFindingToNode(finding interface{}) *Node {
	findingMap, ok := finding.(map[string]interface{})
	if !ok {
		return nil
	}

	node := &Node{
		ID:         fmt.Sprintf("policy-%d", time.Now().UnixNano()),
		Type:       NodeTypeNamespace,
		Name:       oi.getString(findingMap, "namespace", "unknown"),
		Namespace:  oi.getString(findingMap, "namespace", "default"),
		Properties: make(map[string]interface{}),
		RiskScore:  oi.getFloat64(findingMap, "riskScore", 5.0),
		Metadata:   make(map[string]string),
	}

	return node
}

func (oi *OWASPIntegration) convertTelemetryFindingToNode(finding interface{}) *Node {
	findingMap, ok := finding.(map[string]interface{})
	if !ok {
		return nil
	}

	node := &Node{
		ID:         fmt.Sprintf("telemetry-%d", time.Now().UnixNano()),
		Type:       NodeTypePod,
		Name:       oi.getString(findingMap, "name", "unknown"),
		Namespace:  oi.getString(findingMap, "namespace", "default"),
		Properties: make(map[string]interface{}),
		RiskScore:  oi.getFloat64(findingMap, "riskScore", 5.0),
		Metadata:   make(map[string]string),
	}

	return node
}

func (oi *OWASPIntegration) convertAuthFindingToGraph(finding interface{}) ([]*Node, []*Edge) {
	var nodes []*Node
	var edges []*Edge

	findingMap, ok := finding.(map[string]interface{})
	if !ok {
		return nodes, edges
	}

	// Create user node
	userNode := &Node{
		ID:         fmt.Sprintf("user-%d", time.Now().UnixNano()),
		Type:       NodeTypeUser,
		Name:       oi.getString(findingMap, "user", "unknown"),
		Namespace:  "",
		Properties: make(map[string]interface{}),
		RiskScore:  oi.getFloat64(findingMap, "riskScore", 5.0),
		Metadata:   make(map[string]string),
	}
	nodes = append(nodes, userNode)

	// Create service account node
	saNode := &Node{
		ID:         fmt.Sprintf("sa-%d", time.Now().UnixNano()),
		Type:       NodeTypeServiceAccount,
		Name:       oi.getString(findingMap, "serviceAccount", "unknown"),
		Namespace:  oi.getString(findingMap, "namespace", "default"),
		Properties: make(map[string]interface{}),
		RiskScore:  oi.getFloat64(findingMap, "riskScore", 5.0),
		Metadata:   make(map[string]string),
	}
	nodes = append(nodes, saNode)

	// Create edge between user and service account
	edge := &Edge{
		ID:         fmt.Sprintf("edge-%d", time.Now().UnixNano()),
		Source:     userNode.ID,
		Target:     saNode.ID,
		Type:       EdgeTypeCanAccess,
		Weight:     1.0,
		Properties: make(map[string]interface{}),
		RiskScore:  oi.getFloat64(findingMap, "riskScore", 5.0),
		Metadata:   make(map[string]string),
	}
	edges = append(edges, edge)

	return nodes, edges
}

func (oi *OWASPIntegration) convertNetworkFindingToGraph(finding interface{}) ([]*Node, []*Edge) {
	var nodes []*Node
	var edges []*Edge

	findingMap, ok := finding.(map[string]interface{})
	if !ok {
		return nodes, edges
	}

	// Create endpoint node
	endpointNode := &Node{
		ID:         fmt.Sprintf("endpoint-%d", time.Now().UnixNano()),
		Type:       NodeTypeEndpoint,
		Name:       oi.getString(findingMap, "name", "unknown"),
		Namespace:  oi.getString(findingMap, "namespace", "default"),
		Properties: make(map[string]interface{}),
		RiskScore:  oi.getFloat64(findingMap, "riskScore", 5.0),
		Metadata:   make(map[string]string),
	}
	nodes = append(nodes, endpointNode)

	// Create service node
	serviceNode := &Node{
		ID:         fmt.Sprintf("service-%d", time.Now().UnixNano()),
		Type:       NodeTypeService,
		Name:       oi.getString(findingMap, "service", "unknown"),
		Namespace:  oi.getString(findingMap, "namespace", "default"),
		Properties: make(map[string]interface{}),
		RiskScore:  oi.getFloat64(findingMap, "riskScore", 5.0),
		Metadata:   make(map[string]string),
	}
	nodes = append(nodes, serviceNode)

	// Create edge between endpoint and service
	edge := &Edge{
		ID:         fmt.Sprintf("edge-%d", time.Now().UnixNano()),
		Source:     endpointNode.ID,
		Target:     serviceNode.ID,
		Type:       EdgeTypeCanConnect,
		Weight:     1.0,
		Properties: make(map[string]interface{}),
		RiskScore:  oi.getFloat64(findingMap, "riskScore", 5.0),
		Metadata:   make(map[string]string),
	}
	edges = append(edges, edge)

	return nodes, edges
}

func (oi *OWASPIntegration) convertSecretFindingToNode(finding interface{}) *Node {
	findingMap, ok := finding.(map[string]interface{})
	if !ok {
		return nil
	}

	node := &Node{
		ID:         fmt.Sprintf("secret-%d", time.Now().UnixNano()),
		Type:       NodeTypeSecret,
		Name:       oi.getString(findingMap, "name", "unknown"),
		Namespace:  oi.getString(findingMap, "namespace", "default"),
		Properties: make(map[string]interface{}),
		RiskScore:  oi.getFloat64(findingMap, "riskScore", 5.0),
		Metadata:   make(map[string]string),
	}

	return node
}

func (oi *OWASPIntegration) convertComponentFindingToNode(finding interface{}) *Node {
	findingMap, ok := finding.(map[string]interface{})
	if !ok {
		return nil
	}

	node := &Node{
		ID:         fmt.Sprintf("component-%d", time.Now().UnixNano()),
		Type:       NodeTypePod,
		Name:       oi.getString(findingMap, "name", "unknown"),
		Namespace:  oi.getString(findingMap, "namespace", "default"),
		Properties: make(map[string]interface{}),
		RiskScore:  oi.getFloat64(findingMap, "riskScore", 5.0),
		Metadata:   make(map[string]string),
	}

	return node
}

func (oi *OWASPIntegration) convertVulnerabilityFindingToNode(finding interface{}) *Node {
	findingMap, ok := finding.(map[string]interface{})
	if !ok {
		return nil
	}

	node := &Node{
		ID:         fmt.Sprintf("vulnerability-%d", time.Now().UnixNano()),
		Type:       NodeTypePod,
		Name:       oi.getString(findingMap, "name", "unknown"),
		Namespace:  oi.getString(findingMap, "namespace", "default"),
		Properties: make(map[string]interface{}),
		RiskScore:  oi.getFloat64(findingMap, "riskScore", 5.0),
		Metadata:   make(map[string]string),
	}

	return node
}

// Helper methods for adding edges

func (oi *OWASPIntegration) addWorkloadEdges(node *Node) {
	// Add edges to related resources
	// This would be more sophisticated in practice
}

func (oi *OWASPIntegration) addSupplyChainEdges(node *Node) {
	// Add edges to related supply chain elements
}

func (oi *OWASPIntegration) addPolicyEdges(node *Node) {
	// Add edges to related policy elements
}

func (oi *OWASPIntegration) addTelemetryEdges(node *Node) {
	// Add edges to related telemetry elements
}

func (oi *OWASPIntegration) addSecretEdges(node *Node) {
	// Add edges to related secret elements
}

func (oi *OWASPIntegration) addComponentEdges(node *Node) {
	// Add edges to related component elements
}

func (oi *OWASPIntegration) addVulnerabilityEdges(node *Node) {
	// Add edges to related vulnerability elements
}

// Helper methods for data extraction

func (oi *OWASPIntegration) getString(m map[string]interface{}, key, defaultValue string) string {
	if value, ok := m[key].(string); ok {
		return value
	}
	return defaultValue
}

func (oi *OWASPIntegration) getFloat64(m map[string]interface{}, key string, defaultValue float64) float64 {
	if value, ok := m[key].(float64); ok {
		return value
	}
	return defaultValue
}

func (oi *OWASPIntegration) getBool(m map[string]interface{}, key string, defaultValue bool) bool {
	if value, ok := m[key].(bool); ok {
		return value
	}
	return defaultValue
}
