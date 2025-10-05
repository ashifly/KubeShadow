package dashboard

import (
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// WebSocketManager manages WebSocket connections and real-time updates
type WebSocketManager struct {
	clients     map[*websocket.Conn]bool
	clientMutex sync.RWMutex
	upgrader    websocket.Upgrader
	storage     *Storage
}

// NewWebSocketManager creates a new WebSocket manager
func NewWebSocketManager(storage *Storage) *WebSocketManager {
	return &WebSocketManager{
		clients: make(map[*websocket.Conn]bool),
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				return true // Allow all origins for simplicity
			},
		},
		storage: storage,
	}
}

// HandleWebSocket handles WebSocket connections
func (wm *WebSocketManager) HandleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := wm.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade error: %v", err)
		return
	}
	defer conn.Close()

	// Add client to manager
	wm.clientMutex.Lock()
	wm.clients[conn] = true
	wm.clientMutex.Unlock()

	// Remove client when connection closes
	defer func() {
		wm.clientMutex.Lock()
		delete(wm.clients, conn)
		wm.clientMutex.Unlock()
	}()

	log.Printf("🔌 WebSocket client connected")

	// Send initial data
	wm.sendInitialData(conn)

	// Keep connection alive and handle messages
	for {
		_, message, err := conn.ReadMessage()
		if err != nil {
			log.Printf("WebSocket read error: %v", err)
			break
		}

		// Handle incoming messages
		wm.handleClientMessage(conn, message)
	}

	log.Printf("🔌 WebSocket client disconnected")
}

// sendInitialData sends initial data to a new client
func (wm *WebSocketManager) sendInitialData(conn *websocket.Conn) {
	// Send current graph
	graph, err := wm.storage.GetFullGraph()
	if err == nil {
		wm.sendMessage(conn, WebSocketGraphMessage{
			Type:      "graph_initial",
			Data:      graph,
			Timestamp: time.Now(),
		})
	}

	// Send recent commands
	commands, err := wm.storage.GetCommands(20, 0)
	if err == nil {
		wm.sendMessage(conn, WebSocketGraphMessage{
			Type:      "commands_initial",
			Data:      commands,
			Timestamp: time.Now(),
		})
	}

	// Send graph stats
	stats := wm.calculateGraphStats(graph)
	wm.sendMessage(conn, WebSocketGraphMessage{
		Type:      "stats_initial",
		Data:      stats,
		Timestamp: time.Now(),
	})
}

// handleClientMessage handles incoming messages from clients
func (wm *WebSocketManager) handleClientMessage(conn *websocket.Conn, message []byte) {
	var request map[string]interface{}
	if err := json.Unmarshal(message, &request); err != nil {
		log.Printf("Error parsing WebSocket message: %v", err)
		return
	}

	messageType, ok := request["type"].(string)
	if !ok {
		return
	}

	switch messageType {
	case "subscribe":
		// Handle subscription requests
		wm.handleSubscription(conn, request)
	case "filter":
		// Handle filter requests
		wm.handleFilter(conn, request)
	case "export":
		// Handle export requests
		wm.handleExport(conn, request)
	default:
		log.Printf("Unknown WebSocket message type: %s", messageType)
	}
}

// handleSubscription handles client subscription requests
func (wm *WebSocketManager) handleSubscription(conn *websocket.Conn, _ map[string]interface{}) {
	// For now, just acknowledge the subscription
	wm.sendMessage(conn, WebSocketGraphMessage{
		Type:      "subscription_confirmed",
		Data:      map[string]string{"status": "subscribed"},
		Timestamp: time.Now(),
	})
}

// handleFilter handles client filter requests
func (wm *WebSocketManager) handleFilter(conn *websocket.Conn, request map[string]interface{}) {
	// Parse filter parameters
	filter := GraphFilter{}

	if nodeTypes, ok := request["nodeTypes"].([]interface{}); ok {
		for _, nt := range nodeTypes {
			if str, ok := nt.(string); ok {
				filter.NodeTypes = append(filter.NodeTypes, str)
			}
		}
	}

	if edgeTypes, ok := request["edgeTypes"].([]interface{}); ok {
		for _, et := range edgeTypes {
			if str, ok := et.(string); ok {
				filter.EdgeTypes = append(filter.EdgeTypes, str)
			}
		}
	}

	if namespaces, ok := request["namespaces"].([]interface{}); ok {
		for _, ns := range namespaces {
			if str, ok := ns.(string); ok {
				filter.Namespaces = append(filter.Namespaces, str)
			}
		}
	}

	// Apply filter and send filtered graph
	filteredGraph := wm.applyFilter(filter)
	wm.sendMessage(conn, WebSocketGraphMessage{
		Type:      "graph_filtered",
		Data:      filteredGraph,
		Timestamp: time.Now(),
	})
}

// handleExport handles client export requests
func (wm *WebSocketManager) handleExport(conn *websocket.Conn, request map[string]interface{}) {
	format, ok := request["format"].(string)
	if !ok {
		format = "json"
	}

	graph, err := wm.storage.GetFullGraph()
	if err != nil {
		wm.sendMessage(conn, WebSocketGraphMessage{
			Type:      "export_error",
			Data:      map[string]string{"error": "Failed to get graph"},
			Timestamp: time.Now(),
		})
		return
	}

	var exportData interface{}
	switch format {
	case "json":
		exportData = graph
	case "csv":
		exportData = "Type,ID,Name,Namespace,Source,Target,Weight\nnode,example,example-node,default,,,0.0\n"
	case "dot":
		exportData = "digraph AttackGraph {\n  rankdir=LR;\n  node [shape=box];\n}\n"
	case "mermaid":
		exportData = "graph TD\n  A[Start] --> B[End]\n"
	default:
		wm.sendMessage(conn, WebSocketGraphMessage{
			Type:      "export_error",
			Data:      map[string]string{"error": "Unsupported format"},
			Timestamp: time.Now(),
		})
		return
	}

	wm.sendMessage(conn, WebSocketGraphMessage{
		Type:      "export_result",
		Data:      map[string]interface{}{"format": format, "data": exportData},
		Timestamp: time.Now(),
	})
}

// BroadcastGraphDelta broadcasts a graph delta to all connected clients
func (wm *WebSocketManager) BroadcastGraphDelta(commandID string, delta GraphDelta) {
	message := WebSocketGraphMessage{
		Type: "graph_delta",
		Data: GraphDeltaMessage{
			CommandID: commandID,
			DeltaType: delta.Type,
			Nodes:     delta.Nodes,
			Edges:     delta.Edges,
			Timestamp: delta.CreatedAt,
		},
		Timestamp: time.Now(),
	}

	wm.broadcastToAllClients(message)
}

// BroadcastAttackChain broadcasts a new attack chain to all connected clients
func (wm *WebSocketManager) BroadcastAttackChain(chain AttackChain) {
	message := WebSocketGraphMessage{
		Type: "chain_found",
		Data: ChainFoundMessage{
			Chain: chain,
			Risk:  chain.RiskScore,
			Alert: chain.RiskScore > 8.0, // Alert for high-risk chains
		},
		Timestamp: time.Now(),
	}

	wm.broadcastToAllClients(message)
}

// BroadcastCommandFinished broadcasts a command completion
func (wm *WebSocketManager) BroadcastCommandFinished(command *CommandResult) {
	message := WebSocketGraphMessage{
		Type:      "command_finished",
		Data:      command,
		Timestamp: time.Now(),
	}

	wm.broadcastToAllClients(message)
}

// BroadcastStatsUpdate broadcasts updated statistics
func (wm *WebSocketManager) BroadcastStatsUpdate(stats GraphStats) {
	message := WebSocketGraphMessage{
		Type:      "stats_update",
		Data:      stats,
		Timestamp: time.Now(),
	}

	wm.broadcastToAllClients(message)
}

// Helper methods

func (wm *WebSocketManager) sendMessage(conn *websocket.Conn, message WebSocketGraphMessage) {
	if err := conn.WriteJSON(message); err != nil {
		log.Printf("Error sending WebSocket message: %v", err)
		conn.Close()
		wm.clientMutex.Lock()
		delete(wm.clients, conn)
		wm.clientMutex.Unlock()
	}
}

func (wm *WebSocketManager) broadcastToAllClients(message WebSocketGraphMessage) {
	wm.clientMutex.RLock()
	defer wm.clientMutex.RUnlock()

	for client := range wm.clients {
		if err := client.WriteJSON(message); err != nil {
			log.Printf("Error broadcasting to client: %v", err)
			client.Close()
			delete(wm.clients, client)
		}
	}
}

func (wm *WebSocketManager) applyFilter(filter GraphFilter) *AttackGraph {
	graph, err := wm.storage.GetFullGraph()
	if err != nil {
		return &AttackGraph{}
	}

	var filteredNodes []GraphNode
	var filteredEdges []GraphEdge

	// Filter nodes
	for _, node := range graph.Nodes {
		if wm.nodeMatchesFilter(node, filter) {
			filteredNodes = append(filteredNodes, node)
		}
	}

	// Filter edges
	for _, edge := range graph.Edges {
		if wm.edgeMatchesFilter(edge, filter) {
			filteredEdges = append(filteredEdges, edge)
		}
	}

	return &AttackGraph{
		Nodes: filteredNodes,
		Edges: filteredEdges,
	}
}

func (wm *WebSocketManager) nodeMatchesFilter(node GraphNode, filter GraphFilter) bool {
	// Check node type filter
	if len(filter.NodeTypes) > 0 {
		found := false
		for _, nodeType := range filter.NodeTypes {
			if node.Type == nodeType {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Check namespace filter
	if len(filter.Namespaces) > 0 {
		found := false
		for _, namespace := range filter.Namespaces {
			if node.Namespace == namespace {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Check risk score filter
	if risk, ok := node.Metadata["riskScore"].(float64); ok {
		if filter.MinRisk > 0 && risk < filter.MinRisk {
			return false
		}
		if filter.MaxRisk > 0 && risk > filter.MaxRisk {
			return false
		}
	}

	return true
}

func (wm *WebSocketManager) edgeMatchesFilter(edge GraphEdge, filter GraphFilter) bool {
	// Check edge type filter
	if len(filter.EdgeTypes) > 0 {
		found := false
		for _, edgeType := range filter.EdgeTypes {
			if edge.Type == edgeType {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Check weight filter
	if filter.MinRisk > 0 && edge.Weight < filter.MinRisk {
		return false
	}
	if filter.MaxRisk > 0 && edge.Weight > filter.MaxRisk {
		return false
	}

	return true
}

func (wm *WebSocketManager) calculateGraphStats(graph *AttackGraph) GraphStats {
	stats := GraphStats{
		TotalNodes:  len(graph.Nodes),
		TotalEdges:  len(graph.Edges),
		LastUpdated: time.Now(),
	}

	// Calculate high-risk nodes
	highRiskCount := 0
	totalRisk := 0.0
	maxRisk := 0.0

	for _, node := range graph.Nodes {
		if risk, ok := node.Metadata["riskScore"].(float64); ok {
			totalRisk += risk
			if risk > maxRisk {
				maxRisk = risk
			}
			if risk > 7.0 {
				highRiskCount++
			}
		}
	}

	stats.HighRiskNodes = highRiskCount
	stats.MaxRiskScore = maxRisk
	if len(graph.Nodes) > 0 {
		stats.AvgRiskScore = totalRisk / float64(len(graph.Nodes))
	}

	// Calculate critical paths
	stats.CriticalPaths = wm.countCriticalPaths(graph)

	return stats
}

func (wm *WebSocketManager) countCriticalPaths(graph *AttackGraph) int {
	criticalCount := 0
	for _, edge := range graph.Edges {
		if edge.Weight > 8.0 {
			criticalCount++
		}
	}
	return criticalCount
}
