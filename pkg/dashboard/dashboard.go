package dashboard

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

var (
	instance *Dashboard
	once     sync.Once
)

// FeatureFlags controls which enhanced features are enabled
type FeatureFlags struct {
	AttackMap      bool `json:"attackMap"`
	GraphBuilder   bool `json:"graphBuilder"`
	RealTimeWS     bool `json:"realTimeWS"`
	CommandStorage bool `json:"commandStorage"`
	ExportAPI      bool `json:"exportAPI"`
}

// Dashboard manages the web dashboard for KubeShadow
type Dashboard struct {
	server       *http.Server
	storage      *Storage
	graphBuilder *GraphBuilder
	apiHandler   *APIHandler
	wsManager    *WebSocketManager
	frontendMgr  *FrontendManager
	results      []CommandResult
	mutex        sync.RWMutex
	clients      map[*websocket.Conn]bool
	clientMutex  sync.RWMutex
	upgrader     websocket.Upgrader
	stats        DashboardStats
	enabled      bool
	features     FeatureFlags
}

// GetInstance returns the singleton dashboard instance
func GetInstance() *Dashboard {
	once.Do(func() {
		// Initialize storage
		storage, err := NewStorage("kubeshadow.db")
		if err != nil {
			log.Printf("Warning: Failed to initialize storage, using in-memory mode: %v", err)
			storage = nil
		}

		// Initialize components
		graphBuilder := NewGraphBuilder(storage)
		apiHandler := NewAPIHandler(storage, graphBuilder)
		wsManager := NewWebSocketManager(storage)
		frontendMgr := NewFrontendManager()

		instance = &Dashboard{
			storage:      storage,
			graphBuilder: graphBuilder,
			apiHandler:   apiHandler,
			wsManager:    wsManager,
			frontendMgr:  frontendMgr,
			results:      make([]CommandResult, 0),
			clients:      make(map[*websocket.Conn]bool),
			upgrader: websocket.Upgrader{
				CheckOrigin: func(r *http.Request) bool {
					return true // Allow all origins for simplicity
				},
			},
			stats: DashboardStats{
				UptimeStart: time.Now(),
			},
			features: FeatureFlags{
				AttackMap:      true,
				GraphBuilder:   true,
				RealTimeWS:     true,
				CommandStorage: true,
				ExportAPI:      true,
			},
		}
	})
	return instance
}

// Start starts the dashboard web server on the specified port
func (d *Dashboard) Start(port int) error {
	if d.enabled {
		return fmt.Errorf("dashboard is already running")
	}

	// Check if port is available, find alternative if needed
	if !d.isPortAvailable(port) {
		log.Printf("⚠️  Port %d is already in use, searching for alternative...", port)
		availablePort := d.findAvailablePort(port)
		if availablePort == 0 {
			return fmt.Errorf("no available ports found starting from %d", port)
		}
		log.Printf("✅ Found available port: %d", availablePort)
		port = availablePort
	}

	mux := http.NewServeMux()

	// Serve enhanced frontend
	mux.HandleFunc("/", d.frontendMgr.ServeEnhancedDashboard)

	// Legacy endpoints for backward compatibility
	mux.HandleFunc("/api/results", d.handleResults)
	mux.HandleFunc("/api/stats", d.handleStats)
	mux.HandleFunc("/api/publish", d.handlePublish)
	mux.HandleFunc("/api/export/csv", d.handleCSVExport)
	mux.HandleFunc("/api/export/pdf", d.handlePDFExport)
	mux.HandleFunc("/logo.png", d.handleLogo)
	mux.HandleFunc("/ws", d.handleWebSocket)

	// Enhanced API endpoints
	if d.features.CommandStorage {
		d.apiHandler.RegisterRoutes(mux)
	}

	// Enhanced WebSocket endpoint
	if d.features.RealTimeWS {
		mux.HandleFunc("/ws/enhanced", d.wsManager.HandleWebSocket)
	}

	d.server = &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: mux,
	}

	d.enabled = true
	log.Printf("🎯 Dashboard starting on http://localhost:%d", port)
	log.Printf("🌐 Also accessible at: http://127.0.0.1:%d", port)

	go func() {
		if err := d.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("❌ Dashboard server error: %v", err)
			log.Printf("💡 Try using a different port: --dashboard-port 8081")
			log.Printf("💡 Port %d may be in use by another process", port)
		}
	}()

	return nil
}

// Stop stops the dashboard web server
func (d *Dashboard) Stop() error {
	if !d.enabled {
		return nil
	}

	d.enabled = false
	if d.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return d.server.Shutdown(ctx)
	}
	return nil
}

// IsEnabled returns whether the dashboard is currently enabled
func (d *Dashboard) IsEnabled() bool {
	return d.enabled
}

// PublishResult publishes a command result to the dashboard
func (d *Dashboard) PublishResult(result CommandResult) {
	if !d.enabled {
		return
	}

	d.mutex.Lock()
	defer d.mutex.Unlock()

	// Add or update result
	found := false
	for i, existing := range d.results {
		if existing.ID == result.ID {
			d.results[i] = result
			found = true
			break
		}
	}

	if !found {
		d.results = append(d.results, result)
	}

	// Store in database if storage is available
	if d.features.CommandStorage && d.storage != nil {
		go func() {
			if err := d.storage.StoreCommand(&result); err != nil {
				log.Printf("Error storing command in database: %v", err)
			}
		}()
	}

	// Update stats
	d.updateStats()

	// Broadcast to WebSocket clients
	d.broadcastToClients(WebSocketMessage{
		Type: "result",
		Data: result,
	})

	// Broadcast command finished event
	if d.features.RealTimeWS {
		d.wsManager.BroadcastCommandFinished(&result)
	}
}

// GetResults returns all command results
func (d *Dashboard) GetResults() []CommandResult {
	d.mutex.RLock()
	defer d.mutex.RUnlock()

	results := make([]CommandResult, len(d.results))
	copy(results, d.results)
	return results
}

// GetStats returns dashboard statistics
func (d *Dashboard) GetStats() DashboardStats {
	d.mutex.RLock()
	defer d.mutex.RUnlock()
	return d.stats
}

// PublishCommandResult publishes detailed command results with findings
func (d *Dashboard) PublishCommandResult(commandID string, output, errorMsg string, findings []Finding, summary ModuleSummary) {
	if !d.enabled {
		return
	}

	// Store detailed results in database
	if d.features.CommandStorage && d.storage != nil {
		go func() {
			if err := d.storage.StoreCommandResult(commandID, output, errorMsg, findings, summary); err != nil {
				log.Printf("Error storing command result: %v", err)
			}

			// Process with graph builder
			if d.features.GraphBuilder {
				command, err := d.storage.GetCommand(commandID)
				if err == nil {
					if err := d.graphBuilder.ProcessCommandResult(command, findings, summary); err != nil {
						log.Printf("Error processing command result with graph builder: %v", err)
					}
				}
			}
		}()
	}
}

// GetFeatureFlags returns the current feature flags
func (d *Dashboard) GetFeatureFlags() FeatureFlags {
	return d.features
}

// SetFeatureFlags updates the feature flags
func (d *Dashboard) SetFeatureFlags(flags FeatureFlags) {
	d.features = flags
	log.Printf("🔧 Feature flags updated: %+v", flags)
}

// updateStats updates internal statistics
func (d *Dashboard) updateStats() {
	total := len(d.results)
	successful := 0
	failed := 0
	running := 0
	var totalDuration time.Duration
	var lastExecution *time.Time

	for _, result := range d.results {
		switch result.Status {
		case "completed":
			successful++
			totalDuration += result.Duration
		case "error":
			failed++
		case "running":
			running++
		}

		if lastExecution == nil || result.StartTime.After(*lastExecution) {
			lastExecution = &result.StartTime
		}
	}

	d.stats = DashboardStats{
		TotalCommands:   total,
		SuccessfulRuns:  successful,
		FailedRuns:      failed,
		RunningCommands: running,
		AverageTime:     0,
		LastExecution:   lastExecution,
		UptimeStart:     d.stats.UptimeStart,
	}

	if successful > 0 {
		d.stats.AverageTime = totalDuration / time.Duration(successful)
	}
}

// broadcastToClients sends a message to all connected WebSocket clients
func (d *Dashboard) broadcastToClients(message WebSocketMessage) {
	d.clientMutex.RLock()
	defer d.clientMutex.RUnlock()

	for client := range d.clients {
		err := client.WriteJSON(message)
		if err != nil {
			log.Printf("Error sending message to client: %v", err)
			client.Close()
			delete(d.clients, client)
		}
	}
}

// HTTP Handlers

func (d *Dashboard) handleResults(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	results := d.GetResults()
	json.NewEncoder(w).Encode(results)
}

func (d *Dashboard) handleStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	stats := d.GetStats()
	json.NewEncoder(w).Encode(stats)
}

func (d *Dashboard) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := d.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade error: %v", err)
		return
	}
	defer conn.Close()

	d.clientMutex.Lock()
	d.clients[conn] = true
	d.clientMutex.Unlock()

	defer func() {
		d.clientMutex.Lock()
		delete(d.clients, conn)
		d.clientMutex.Unlock()
	}()

	// Send initial data
	d.broadcastToClients(WebSocketMessage{
		Type: "stats",
		Data: d.GetStats(),
	})

	// Keep connection alive
	for {
		_, _, err := conn.ReadMessage()
		if err != nil {
			break
		}
	}
}

func (d *Dashboard) handleCSVExport(w http.ResponseWriter, r *http.Request) {
	results := d.GetResults()
	stats := d.GetStats()

	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", "attachment; filename=kubeshadow-results.csv")

	csv := generateCSV(results, stats)
	if _, err := w.Write([]byte(csv)); err != nil {
		log.Printf("Error writing CSV export: %v", err)
		http.Error(w, "Failed to export CSV", http.StatusInternalServerError)
		return
	}
}

func (d *Dashboard) handlePDFExport(w http.ResponseWriter, r *http.Request) {
	results := d.GetResults()
	stats := d.GetStats()

	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Disposition", "attachment; filename=kubeshadow-dashboard.pdf")

	pdf := generatePDF(results, stats)
	if _, err := w.Write(pdf); err != nil {
		log.Printf("Error writing PDF export: %v", err)
		http.Error(w, "Failed to export PDF", http.StatusInternalServerError)
		return
	}
}

func (d *Dashboard) handlePublish(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var result CommandResult
	if err := json.NewDecoder(r.Body).Decode(&result); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	d.PublishResult(result)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "success"})
}

func (d *Dashboard) handleLogo(w http.ResponseWriter, r *http.Request) {
	// Serve the logo.png file
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "public, max-age=86400") // Cache for 24 hours

	// Read the logo file from the current directory
	logoData, err := os.ReadFile("logo.png")
	if err != nil {
		log.Printf("Error reading logo file: %v", err)
		http.NotFound(w, r)
		return
	}

	if _, err := w.Write(logoData); err != nil {
		log.Printf("Error writing logo data: %v", err)
	}
}

// isPortAvailable checks if a port is available for binding
func (d *Dashboard) isPortAvailable(port int) bool {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return false
	}
	ln.Close()
	return true
}

// findAvailablePort finds an available port starting from the given port
func (d *Dashboard) findAvailablePort(startPort int) int {
	for port := startPort; port < startPort+100; port++ {
		if d.isPortAvailable(port) {
			return port
		}
	}
	return 0 // No available port found
}
