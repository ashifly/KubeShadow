package dashboard

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
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
			// Check if it's a CGO error - this is expected and fine, fail silently
			errStr := err.Error()
			if errStr == "Binary was compiled with 'CGO_ENABLED=0', go-sqlite3 requires cgo to work. This is a stub" ||
				errStr == "sql: unknown driver \"sqlite3\" (forgotten import?)" ||
				errStr == "CGO is disabled: go-sqlite3 requires CGO. Build with CGO_ENABLED=1 or use in-memory mode" ||
				strings.Contains(errStr, "CGO_ENABLED=0") ||
				strings.Contains(errStr, "sqlite3") {
				// Silent fallback to in-memory mode - this is expected behavior
				// No warning needed - dashboard works fine in in-memory mode
				storage = nil
			} else {
				// Only log non-CGO errors (actual database problems)
				// These are rare and worth logging
				log.Printf("⚠️  Storage unavailable, using in-memory mode: %v", err)
				storage = nil
			}
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
		Addr:    fmt.Sprintf("0.0.0.0:%d", port), // Listen on all interfaces for remote access
		Handler: mux,
	}

	d.enabled = true
	
	// Get all network IP addresses
	ips := d.getNetworkIPs(port)
	
	// Get public IP address
	publicIP := d.getPublicIP()
	
	log.Printf("🎯 Dashboard starting on http://localhost:%d", port)
	log.Println("")
	log.Println("═══════════════════════════════════════════════════════════")
	log.Println("🌐 DASHBOARD ACCESSIBLE FROM ANYWHERE")
	log.Println("═══════════════════════════════════════════════════════════")
	
	// Show public IP first if available
	if publicIP != "" {
		log.Printf("🌍 VM PUBLIC IP: http://%s:%d", publicIP, port)
		log.Printf("   ↳ This is your VM's public IP - accessible from anywhere on the internet")
		log.Printf("   ↳ Share this URL to allow remote access to the dashboard")
		log.Println("")
	} else {
		log.Println("⚠️  Could not detect VM public IP (may be behind NAT/firewall)")
		log.Println("   ↳ Dashboard is still accessible via local network IPs shown below")
		log.Println("")
	}
	
	// Show local network IPs
	if len(ips) > 0 {
		log.Println("📡 LOCAL NETWORK IPs:")
		for _, ip := range ips {
			log.Printf("   • http://%s:%d", ip, port)
		}
		log.Println("")
	}
	
	log.Printf("💻 LOCAL ACCESS: http://localhost:%d", port)
	log.Println("═══════════════════════════════════════════════════════════")
	log.Println("")

	go func() {
		if err := d.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("❌ Dashboard server error: %v", err)
			log.Printf("💡 Try using a different port: --dashboard-port 8081")
			log.Printf("💡 Port %d may be in use by another process", port)
		}
	}()

	return nil
}

// getNetworkIPs returns all non-loopback IP addresses for the machine
func (d *Dashboard) getNetworkIPs(port int) []string {
	var ips []string
	
	// Get all network interfaces
	interfaces, err := net.Interfaces()
	if err != nil {
		return ips
	}
	
	for _, iface := range interfaces {
		// Skip loopback and down interfaces
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			
			if ip == nil || ip.IsLoopback() {
				continue
			}
			
			// Only include IPv4 addresses
			if ip.To4() != nil {
				ips = append(ips, ip.String())
			}
		}
	}
	
	// Remove duplicates
	seen := make(map[string]bool)
	var uniqueIPs []string
	for _, ip := range ips {
		if !seen[ip] {
			seen[ip] = true
			uniqueIPs = append(uniqueIPs, ip)
		}
	}
	
	return uniqueIPs
}

// getPublicIP attempts to get the public IP address of the machine
func (d *Dashboard) getPublicIP() string {
	// List of public IP services to try
	services := []string{
		"https://api.ipify.org",
		"https://ifconfig.me/ip",
		"https://icanhazip.com",
		"https://checkip.amazonaws.com",
		"https://ipinfo.io/ip",
	}
	
	client := &http.Client{
		Timeout: 3 * time.Second,
	}
	
	// Try each service until one works
	for _, service := range services {
		resp, err := client.Get(service)
		if err != nil {
			continue
		}
		defer resp.Body.Close()
		
		if resp.StatusCode == http.StatusOK {
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				continue
			}
			
			ip := strings.TrimSpace(string(body))
			// Validate it's a valid IP address
			if net.ParseIP(ip) != nil {
				return ip
			}
		}
	}
	
	// If all services fail, return empty string
	return ""
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
				// Only log non-CGO errors (actual database problems)
				// CGO errors are expected and handled silently
				errStr := err.Error()
				if !strings.Contains(errStr, "CGO_ENABLED=0") && 
				   !strings.Contains(errStr, "sqlite3") &&
				   !strings.Contains(errStr, "CGO is disabled") {
					log.Printf("Error storing command in database: %v", err)
				}
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
				// Only log non-CGO errors (actual database problems)
				// CGO errors are expected and handled silently
				errStr := err.Error()
				if !strings.Contains(errStr, "CGO_ENABLED=0") && 
				   !strings.Contains(errStr, "sqlite3") &&
				   !strings.Contains(errStr, "CGO is disabled") {
					log.Printf("Error storing command result: %v", err)
				}
			}

			// Process with graph builder
			if d.features.GraphBuilder && d.storage != nil {
				command, err := d.storage.GetCommand(commandID)
				if err == nil {
					if err := d.graphBuilder.ProcessCommandResult(command, findings, summary); err != nil {
						// Only log non-CGO errors
						errStr := err.Error()
						if !strings.Contains(errStr, "CGO_ENABLED=0") && 
						   !strings.Contains(errStr, "sqlite3") &&
						   !strings.Contains(errStr, "CGO is disabled") {
							log.Printf("Error processing command result with graph builder: %v", err)
						}
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
