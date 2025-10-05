package dashboard

import (
	"time"
)

// GraphNode represents a node in the attack graph
type GraphNode struct {
	ID        string                 `json:"id"`
	Type      string                 `json:"type"`      // "pod", "service", "secret", "sa", "role", "user", "namespace", "cloud-resource"
	Name      string                 `json:"name"`
	Namespace string                 `json:"namespace,omitempty"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// GraphEdge represents an edge in the attack graph
type GraphEdge struct {
	ID       string                 `json:"id"`
	SourceID string                 `json:"sourceId"`
	TargetID string                 `json:"targetId"`
	Type     string                 `json:"type"`     // "access", "privilege-escalation", "network", "rbac", "cloud-permission"
	Weight   float64                `json:"weight"`   // Risk score or importance
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// AttackGraph represents the complete attack graph
type AttackGraph struct {
	Nodes []GraphNode `json:"nodes"`
	Edges []GraphEdge `json:"edges"`
}

// GraphDelta represents a change to the attack graph
type GraphDelta struct {
	ID        int          `json:"id"`
	CommandID string       `json:"commandId"`
	Type      string       `json:"type"` // "add", "update", "remove"
	Nodes     []GraphNode  `json:"nodes"`
	Edges     []GraphEdge  `json:"edges"`
	CreatedAt time.Time    `json:"createdAt"`
}

// AttackChain represents a potential attack path
type AttackChain struct {
	ID          string      `json:"id"`
	Source      string      `json:"source"`      // Starting point
	Target      string      `json:"target"`      // End goal
	Path        []string    `json:"path"`        // Node IDs in the path
	RiskScore   float64     `json:"riskScore"`   // Overall risk score
	Steps       []ChainStep `json:"steps"`       // Detailed steps
	Confidence  float64     `json:"confidence"`  // Confidence in the chain
	LastUpdated time.Time   `json:"lastUpdated"`
}

// ChainStep represents a single step in an attack chain
type ChainStep struct {
	From        string                 `json:"from"`
	To          string                 `json:"to"`
	Action      string                 `json:"action"`      // What action is taken
	Privilege   string                 `json:"privilege"`   // What privilege is gained
	Requirement string                 `json:"requirement"` // What's needed for this step
	Risk        float64                `json:"risk"`        // Risk of this step
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// GraphFilter represents filters for the attack graph
type GraphFilter struct {
	NodeTypes   []string `json:"nodeTypes,omitempty"`
	EdgeTypes   []string `json:"edgeTypes,omitempty"`
	Namespaces  []string `json:"namespaces,omitempty"`
	MinRisk     float64  `json:"minRisk,omitempty"`
	MaxRisk     float64  `json:"maxRisk,omitempty"`
	TimeRange   *TimeRange `json:"timeRange,omitempty"`
}

// TimeRange represents a time range filter
type TimeRange struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

// GraphVisualization represents visualization settings
type GraphVisualization struct {
	Layout      string            `json:"layout"`      // "hierarchical", "force", "circular"
	Theme       string            `json:"theme"`      // "dark", "light", "cyber"
	NodeSize    string            `json:"nodeSize"`    // "fixed", "risk", "connections"
	EdgeWidth   string            `json:"edgeWidth"`   // "fixed", "weight", "risk"
	Colors      map[string]string `json:"colors"`      // Custom color scheme
	Animations  bool              `json:"animations"`  // Enable animations
	Timeline    bool              `json:"timeline"`     // Show timeline
}

// GraphExport represents export settings
type GraphExport struct {
	Format      string            `json:"format"`      // "json", "csv", "dot", "mermaid"
	IncludeData bool              `json:"includeData"` // Include node/edge data
	Filter      *GraphFilter      `json:"filter,omitempty"`
	Visualization *GraphVisualization `json:"visualization,omitempty"`
}

// GraphStats represents statistics about the attack graph
type GraphStats struct {
	TotalNodes     int     `json:"totalNodes"`
	TotalEdges     int     `json:"totalEdges"`
	HighRiskNodes  int     `json:"highRiskNodes"`
	CriticalPaths  int     `json:"criticalPaths"`
	AvgRiskScore   float64 `json:"avgRiskScore"`
	MaxRiskScore   float64 `json:"maxRiskScore"`
	LastUpdated    time.Time `json:"lastUpdated"`
}

// WebSocketGraphMessage represents WebSocket messages for graph updates
type WebSocketGraphMessage struct {
	Type      string      `json:"type"`      // "graph_delta", "chain_found", "stats_update"
	Data      interface{} `json:"data"`
	Timestamp time.Time   `json:"timestamp"`
}

// GraphDeltaMessage represents a graph delta message
type GraphDeltaMessage struct {
	CommandID string      `json:"commandId"`
	DeltaType string      `json:"deltaType"`
	Nodes     []GraphNode `json:"nodes"`
	Edges     []GraphEdge `json:"edges"`
	Timestamp time.Time   `json:"timestamp"`
}

// ChainFoundMessage represents a new attack chain found
type ChainFoundMessage struct {
	Chain AttackChain `json:"chain"`
	Risk  float64     `json:"risk"`
	Alert bool        `json:"alert"` // Whether this should trigger an alert
}
