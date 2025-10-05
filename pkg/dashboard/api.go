package dashboard

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"
)

// APIHandler handles REST API endpoints for the enhanced dashboard
type APIHandler struct {
	storage      *Storage
	graphBuilder *GraphBuilder
}

// NewAPIHandler creates a new API handler
func NewAPIHandler(storage *Storage, graphBuilder *GraphBuilder) *APIHandler {
	return &APIHandler{
		storage:      storage,
		graphBuilder: graphBuilder,
	}
}

// RegisterRoutes registers all API routes
func (api *APIHandler) RegisterRoutes(mux *http.ServeMux) {
	// Command management endpoints
	mux.HandleFunc("/api/v1/commands", api.handleCommands)
	mux.HandleFunc("/api/v1/commands/", api.handleCommandByID)
	mux.HandleFunc("/api/v1/commands/{id}/results", api.handleCommandResults)
	
	// Graph endpoints
	mux.HandleFunc("/api/v1/graph", api.handleGraph)
	mux.HandleFunc("/api/v1/graph/deltas", api.handleGraphDeltas)
	mux.HandleFunc("/api/v1/graph/chains", api.handleAttackChains)
	mux.HandleFunc("/api/v1/graph/stats", api.handleGraphStats)
	
	// Export endpoints
	mux.HandleFunc("/api/v1/export/graph", api.handleGraphExport)
	mux.HandleFunc("/api/v1/export/commands", api.handleCommandsExport)
}

// handleCommands handles GET /api/v1/commands
func (api *APIHandler) handleCommands(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse query parameters
	limit := 50
	offset := 0
	
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 1000 {
			limit = l
		}
	}
	
	if offsetStr := r.URL.Query().Get("offset"); offsetStr != "" {
		if o, err := strconv.Atoi(offsetStr); err == nil && o >= 0 {
			offset = o
		}
	}

	commands, err := api.storage.GetCommands(limit, offset)
	if err != nil {
		log.Printf("Error getting commands: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"commands": commands,
		"limit":    limit,
		"offset":   offset,
		"total":    len(commands),
	})
}

// handleCommandByID handles GET /api/v1/commands/{id}
func (api *APIHandler) handleCommandByID(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract command ID from URL path
	commandID := r.URL.Path[len("/api/v1/commands/"):]
	if commandID == "" {
		http.Error(w, "Command ID required", http.StatusBadRequest)
		return
	}

	command, err := api.storage.GetCommand(commandID)
	if err != nil {
		log.Printf("Error getting command %s: %v", commandID, err)
		http.Error(w, "Command not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(command)
}

// handleCommandResults handles POST /api/v1/commands/{id}/results
func (api *APIHandler) handleCommandResults(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract command ID from URL path
	commandID := r.URL.Path[len("/api/v1/commands/"):]
	if commandID == "" {
		http.Error(w, "Command ID required", http.StatusBadRequest)
		return
	}

	var request struct {
		Output   string         `json:"output"`
		ErrorMsg string         `json:"errorMsg,omitempty"`
		Findings []Finding      `json:"findings,omitempty"`
		Summary  ModuleSummary  `json:"summary,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Store the command result
	err := api.storage.StoreCommandResult(commandID, request.Output, request.ErrorMsg, request.Findings, request.Summary)
	if err != nil {
		log.Printf("Error storing command result: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Get the command to process with graph builder
	command, err := api.storage.GetCommand(commandID)
	if err != nil {
		log.Printf("Error getting command for graph processing: %v", err)
	} else {
		// Process with graph builder
		go func() {
			if err := api.graphBuilder.ProcessCommandResult(command, request.Findings, request.Summary); err != nil {
				log.Printf("Error processing command result with graph builder: %v", err)
			}
		}()
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "success"})
}

// handleGraph handles GET /api/v1/graph
func (api *APIHandler) handleGraph(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	graph, err := api.storage.GetFullGraph()
	if err != nil {
		log.Printf("Error getting graph: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(graph)
}

// handleGraphDeltas handles GET /api/v1/graph/deltas
func (api *APIHandler) handleGraphDeltas(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	commandID := r.URL.Query().Get("commandId")
	if commandID == "" {
		http.Error(w, "commandId parameter required", http.StatusBadRequest)
		return
	}

	deltas, err := api.storage.GetGraphDeltas(commandID)
	if err != nil {
		log.Printf("Error getting graph deltas: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"deltas": deltas,
		"count":  len(deltas),
	})
}

// handleAttackChains handles GET /api/v1/graph/chains
func (api *APIHandler) handleAttackChains(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// For now, return empty chains - this would be implemented with a proper chain storage
	chains := []AttackChain{}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"chains": chains,
		"count": len(chains),
	})
}

// handleGraphStats handles GET /api/v1/graph/stats
func (api *APIHandler) handleGraphStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	graph, err := api.storage.GetFullGraph()
	if err != nil {
		log.Printf("Error getting graph for stats: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	stats := api.calculateGraphStats(graph)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

// handleGraphExport handles GET /api/v1/export/graph
func (api *APIHandler) handleGraphExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	format := r.URL.Query().Get("format")
	if format == "" {
		format = "json"
	}

	graph, err := api.storage.GetFullGraph()
	if err != nil {
		log.Printf("Error getting graph for export: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	switch format {
	case "json":
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(graph)
	case "csv":
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", "attachment; filename=attack-graph.csv")
		api.exportGraphCSV(w, graph)
	case "dot":
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Disposition", "attachment; filename=attack-graph.dot")
		api.exportGraphDOT(w, graph)
	case "mermaid":
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Disposition", "attachment; filename=attack-graph.mmd")
		api.exportGraphMermaid(w, graph)
	default:
		http.Error(w, "Unsupported format", http.StatusBadRequest)
	}
}

// handleCommandsExport handles GET /api/v1/export/commands
func (api *APIHandler) handleCommandsExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	format := r.URL.Query().Get("format")
	if format == "" {
		format = "json"
	}

	commands, err := api.storage.GetCommands(1000, 0) // Get up to 1000 commands
	if err != nil {
		log.Printf("Error getting commands for export: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	switch format {
	case "json":
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"commands": commands,
			"exported": time.Now(),
		})
	case "csv":
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", "attachment; filename=commands.csv")
		api.exportCommandsCSV(w, commands)
	default:
		http.Error(w, "Unsupported format", http.StatusBadRequest)
	}
}

// Helper methods for exports and stats

func (api *APIHandler) calculateGraphStats(graph *AttackGraph) GraphStats {
	stats := GraphStats{
		TotalNodes: len(graph.Nodes),
		TotalEdges: len(graph.Edges),
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

	// Calculate critical paths (simplified)
	stats.CriticalPaths = api.countCriticalPaths(graph)

	return stats
}

func (api *APIHandler) countCriticalPaths(graph *AttackGraph) int {
	// Simple implementation - count paths with high risk
	criticalCount := 0
	for _, edge := range graph.Edges {
		if edge.Weight > 8.0 {
			criticalCount++
		}
	}
	return criticalCount
}

func (api *APIHandler) exportGraphCSV(w http.ResponseWriter, graph *AttackGraph) {
	fmt.Fprintln(w, "Type,ID,Name,Namespace,Source,Target,Weight,Metadata")
	
	// Export nodes
	for _, node := range graph.Nodes {
		metadata := ""
		if len(node.Metadata) > 0 {
			if data, err := json.Marshal(node.Metadata); err == nil {
				metadata = string(data)
			}
		}
		fmt.Fprintf(w, "node,%s,%s,%s,,,%f,%s\n", 
			node.ID, node.Name, node.Namespace, 0.0, metadata)
	}
	
	// Export edges
	for _, edge := range graph.Edges {
		metadata := ""
		if len(edge.Metadata) > 0 {
			if data, err := json.Marshal(edge.Metadata); err == nil {
				metadata = string(data)
			}
		}
		fmt.Fprintf(w, "edge,%s,,,%s,%s,%f,%s\n", 
			edge.ID, edge.SourceID, edge.TargetID, edge.Weight, metadata)
	}
}

func (api *APIHandler) exportGraphDOT(w http.ResponseWriter, graph *AttackGraph) {
	fmt.Fprintln(w, "digraph AttackGraph {")
	fmt.Fprintln(w, "  rankdir=LR;")
	fmt.Fprintln(w, "  node [shape=box, style=filled];")
	
	// Add nodes
	for _, node := range graph.Nodes {
		color := "lightblue"
		if risk, ok := node.Metadata["riskScore"].(float64); ok && risk > 7.0 {
			color = "red"
		} else if risk > 5.0 {
			color = "orange"
		}
		
		fmt.Fprintf(w, "  \"%s\" [label=\"%s\", fillcolor=%s];\n", 
			node.ID, node.Name, color)
	}
	
	// Add edges
	for _, edge := range graph.Edges {
		penwidth := 1.0
		if edge.Weight > 5.0 {
			penwidth = 3.0
		} else if edge.Weight > 3.0 {
			penwidth = 2.0
		}
		
		fmt.Fprintf(w, "  \"%s\" -> \"%s\" [penwidth=%.1f, label=\"%.1f\"];\n", 
			edge.SourceID, edge.TargetID, penwidth, edge.Weight)
	}
	
	fmt.Fprintln(w, "}")
}

func (api *APIHandler) exportGraphMermaid(w http.ResponseWriter, graph *AttackGraph) {
	fmt.Fprintln(w, "graph TD")
	
	// Add nodes
	for _, node := range graph.Nodes {
		style := ""
		if risk, ok := node.Metadata["riskScore"].(float64); ok && risk > 7.0 {
			style = ":::high-risk"
		} else if risk > 5.0 {
			style = ":::medium-risk"
		}
		
		fmt.Fprintf(w, "  %s[\"%s\"]%s\n", 
			node.ID, node.Name, style)
	}
	
	// Add edges
	for _, edge := range graph.Edges {
		fmt.Fprintf(w, "  %s -->|%.1f| %s\n", 
			edge.SourceID, edge.Weight, edge.TargetID)
	}
	
	// Add styles
	fmt.Fprintln(w, "  classDef high-risk fill:#ff6b6b,stroke:#d63031,stroke-width:3px")
	fmt.Fprintln(w, "  classDef medium-risk fill:#fdcb6e,stroke:#e17055,stroke-width:2px")
}

func (api *APIHandler) exportCommandsCSV(w http.ResponseWriter, commands []*CommandResult) {
	fmt.Fprintln(w, "ID,Module,Command,Status,StartTime,EndTime,Duration,ExitCode,Error")
	
	for _, cmd := range commands {
		endTime := ""
		if cmd.EndTime != nil {
			endTime = cmd.EndTime.Format(time.RFC3339)
		}
		
		fmt.Fprintf(w, "%s,%s,%s,%s,%s,%s,%d,%d,\"%s\"\n",
			cmd.ID, cmd.Module, cmd.Command, cmd.Status,
			cmd.StartTime.Format(time.RFC3339), endTime,
			cmd.Duration.Nanoseconds(), cmd.ExitCode, cmd.ErrorMsg)
	}
}
