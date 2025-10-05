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

// Dashboard manages the web dashboard for KubeShadow
type Dashboard struct {
	server      *http.Server
	results     []CommandResult
	mutex       sync.RWMutex
	clients     map[*websocket.Conn]bool
	clientMutex sync.RWMutex
	upgrader    websocket.Upgrader
	stats       DashboardStats
	enabled     bool
}

// GetInstance returns the singleton dashboard instance
func GetInstance() *Dashboard {
	once.Do(func() {
		instance = &Dashboard{
			results: make([]CommandResult, 0),
			clients: make(map[*websocket.Conn]bool),
			upgrader: websocket.Upgrader{
				CheckOrigin: func(r *http.Request) bool {
					return true // Allow all origins for simplicity
				},
			},
			stats: DashboardStats{
				UptimeStart: time.Now(),
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

	// Serve static files
	mux.HandleFunc("/", d.handleHome)
	mux.HandleFunc("/api/results", d.handleResults)
	mux.HandleFunc("/api/stats", d.handleStats)
	mux.HandleFunc("/api/export/csv", d.handleCSVExport)
	mux.HandleFunc("/api/export/pdf", d.handlePDFExport)
	mux.HandleFunc("/logo.png", d.handleLogo)
	mux.HandleFunc("/ws", d.handleWebSocket)

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

	// Update stats
	d.updateStats()

	// Broadcast to WebSocket clients
	d.broadcastToClients(WebSocketMessage{
		Type: "result",
		Data: result,
	})
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

func (d *Dashboard) handleHome(w http.ResponseWriter, r *http.Request) {
	html := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>KubeShadow Dashboard</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            color: #333;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .header {
            text-align: center;
            color: white;
            margin-bottom: 30px;
        }
        
        .logo {
            width: 120px;
            height: 120px;
            margin-bottom: 20px;
            border-radius: 15px;
            box-shadow: 0 8px 16px rgba(0,0,0,0.3);
            transition: transform 0.3s ease;
        }
        
        .logo:hover {
            transform: scale(1.05);
        }
        
        .header h1 {
            font-size: 2.5rem;
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .stat-card {
            background: rgba(255, 255, 255, 0.95);
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            text-align: center;
            backdrop-filter: blur(10px);
        }
        
        .stat-card h3 {
            color: #667eea;
            font-size: 1.1rem;
            margin-bottom: 10px;
        }
        
        .stat-card .value {
            font-size: 2rem;
            font-weight: bold;
            color: #333;
        }
        
        .results-section {
            background: rgba(255, 255, 255, 0.95);
            border-radius: 10px;
            padding: 20px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            backdrop-filter: blur(10px);
        }
        
        .results-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
        }
        
        .results-header h2 {
            color: #667eea;
        }
        
        .status-indicator {
            width: 12px;
            height: 12px;
            border-radius: 50%;
            display: inline-block;
            margin-right: 8px;
        }
        
        .status-running { background-color: #ffc107; }
        .status-completed { background-color: #28a745; }
        .status-error { background-color: #dc3545; }
        
        .result-card {
            border: 1px solid #e0e0e0;
            border-radius: 8px;
            padding: 15px;
            margin-bottom: 15px;
            transition: all 0.3s ease;
        }
        
        .result-card:hover {
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
            transform: translateY(-2px);
        }
        
        .result-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }
        
        .command-name {
            font-weight: bold;
            font-size: 1.1rem;
            color: #333;
        }
        
        .timestamp {
            color: #666;
            font-size: 0.9rem;
        }
        
        .result-details {
            color: #555;
            line-height: 1.4;
        }
        
        .output-preview {
            background: #f8f9fa;
            padding: 10px;
            border-radius: 4px;
            margin-top: 10px;
            font-family: 'Courier New', monospace;
            font-size: 0.9rem;
            max-height: 100px;
            overflow-y: auto;
            white-space: pre-wrap;
        }
        
        .connection-status {
            position: fixed;
            top: 20px;
            right: 20px;
            padding: 10px 15px;
            border-radius: 5px;
            color: white;
            font-weight: bold;
        }
        
        .connected { background-color: #28a745; }
        .disconnected { background-color: #dc3545; }
        
        .no-results {
            text-align: center;
            padding: 40px;
            color: #666;
        }
        
        .header-buttons {
            display: flex;
            gap: 10px;
            align-items: center;
        }
        
        .export-btn, .refresh-btn {
            border: none;
            padding: 8px 16px;
            border-radius: 5px;
            cursor: pointer;
            transition: all 0.3s ease;
            font-weight: 500;
            font-size: 0.9rem;
        }
        
        .refresh-btn {
            background: #667eea;
            color: white;
        }
        
        .refresh-btn:hover {
            background: #5a6fd8;
            transform: translateY(-1px);
        }
        
        .csv-btn {
            background: #28a745;
            color: white;
        }
        
        .csv-btn:hover {
            background: #218838;
            transform: translateY(-1px);
        }
        
        .pdf-btn {
            background: #dc3545;
            color: white;
        }
        
        .pdf-btn:hover {
            background: #c82333;
            transform: translateY(-1px);
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <img src="/logo.png" alt="KubeShadow Logo" class="logo">
            <h1>KubeShadow Dashboard</h1>
            <p>Real-time monitoring of security testing operations</p>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <h3>Total Commands</h3>
                <div class="value" id="total-commands">0</div>
            </div>
            <div class="stat-card">
                <h3>Successful</h3>
                <div class="value" id="successful-runs">0</div>
            </div>
            <div class="stat-card">
                <h3>Failed</h3>
                <div class="value" id="failed-runs">0</div>
            </div>
            <div class="stat-card">
                <h3>Running</h3>
                <div class="value" id="running-commands">0</div>
            </div>
            <div class="stat-card">
                <h3>Avg Duration</h3>
                <div class="value" id="avg-duration">0ms</div>
            </div>
        </div>
        
        <div class="results-section">
        <div class="results-header">
            <h2>Command Results</h2>
            <div class="header-buttons">
                <button class="export-btn csv-btn" onclick="downloadCSV()">📊 Export CSV</button>
                <button class="export-btn pdf-btn" onclick="downloadPDF()">📄 Export PDF</button>
                <button class="refresh-btn" onclick="refreshData()">🔄 Refresh</button>
            </div>
        </div>
            <div id="results-container">
                <div class="no-results">
                    No command results yet. Run a KubeShadow command with the --dashboard flag to see results here.
                </div>
            </div>
        </div>
    </div>
    
    <div id="connection-status" class="connection-status disconnected">
        Disconnected
    </div>
    
    <script>
        let ws;
        let connectionStatus = document.getElementById('connection-status');
        
        function connectWebSocket() {
            const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
            ws = new WebSocket(protocol + '//' + window.location.host + '/ws');
            
            ws.onopen = function() {
                connectionStatus.textContent = 'Connected';
                connectionStatus.className = 'connection-status connected';
                console.log('WebSocket connected');
            };
            
            ws.onmessage = function(event) {
                const message = JSON.parse(event.data);
                handleWebSocketMessage(message);
            };
            
            ws.onclose = function() {
                connectionStatus.textContent = 'Disconnected';
                connectionStatus.className = 'connection-status disconnected';
                console.log('WebSocket disconnected, attempting to reconnect...');
                setTimeout(connectWebSocket, 3000);
            };
            
            ws.onerror = function(error) {
                console.error('WebSocket error:', error);
            };
        }
        
        function handleWebSocketMessage(message) {
            switch(message.type) {
                case 'result':
                    updateResult(message.data);
                    break;
                case 'stats':
                    updateStats(message.data);
                    break;
            }
        }
        
        function updateResult(result) {
            refreshData(); // Simple approach: refresh all data
        }
        
        function updateStats(stats) {
            document.getElementById('total-commands').textContent = stats.totalCommands;
            document.getElementById('successful-runs').textContent = stats.successfulRuns;
            document.getElementById('failed-runs').textContent = stats.failedRuns;
            document.getElementById('running-commands').textContent = stats.runningCommands;
            
            if (stats.averageTime) {
                const avgMs = Math.round(stats.averageTime / 1000000); // Convert nanoseconds to milliseconds
                document.getElementById('avg-duration').textContent = avgMs + 'ms';
            }
        }
        
        function refreshData() {
            Promise.all([
                fetch('/api/results').then(r => r.json()),
                fetch('/api/stats').then(r => r.json())
            ]).then(([results, stats]) => {
                updateStats(stats);
                renderResults(results);
            }).catch(err => {
                console.error('Error fetching data:', err);
            });
        }
        
        function downloadCSV() {
            fetch('/api/export/csv')
                .then(response => {
                    if (!response.ok) throw new Error('Failed to export CSV');
                    return response.blob();
                })
                .then(blob => {
                    const url = window.URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = ` + "`" + `kubeshadow-results-${new Date().toISOString().split('T')[0]}.csv` + "`" + `;
                    document.body.appendChild(a);
                    a.click();
                    window.URL.revokeObjectURL(url);
                    document.body.removeChild(a);
                })
                .catch(err => {
                    console.error('Error downloading CSV:', err);
                    alert('Failed to download CSV file');
                });
        }
        
        function downloadPDF() {
            // Show loading indicator
            const pdfBtn = document.querySelector('.pdf-btn');
            const originalText = pdfBtn.textContent;
            pdfBtn.textContent = '📄 Generating...';
            pdfBtn.disabled = true;
            
            fetch('/api/export/pdf')
                .then(response => {
                    if (!response.ok) throw new Error('Failed to export PDF');
                    return response.blob();
                })
                .then(blob => {
                    const url = window.URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = ` + "`" + `kubeshadow-dashboard-${new Date().toISOString().split('T')[0]}.pdf` + "`" + `;
                    document.body.appendChild(a);
                    a.click();
                    window.URL.revokeObjectURL(url);
                    document.body.removeChild(a);
                })
                .catch(err => {
                    console.error('Error downloading PDF:', err);
                    alert('Failed to download PDF file');
                })
                .finally(() => {
                    pdfBtn.textContent = originalText;
                    pdfBtn.disabled = false;
                });
        }
        
        function renderResults(results) {
            const container = document.getElementById('results-container');
            
            if (results.length === 0) {
                container.innerHTML = '<div class="no-results">No command results yet. Run a KubeShadow command with the --dashboard flag to see results here.</div>';
                return;
            }
            
            // Sort results by start time (newest first)
            results.sort((a, b) => new Date(b.startTime) - new Date(a.startTime));
            
            container.innerHTML = results.map(result => {
                const startTime = new Date(result.startTime);
                const duration = result.duration ? Math.round(result.duration / 1000000) : 0;
                const outputPreview = result.output ? result.output.substring(0, 200) + (result.output.length > 200 ? '...' : '') : '';
                
                return ` + "`" + `
                    <div class="result-card">
                        <div class="result-header">
                            <div class="command-name">
                                <span class="status-indicator status-${result.status}"></span>
                                ${result.module}: ${result.command}
                            </div>
                            <div class="timestamp">${startTime.toLocaleString()}</div>
                        </div>
                        <div class="result-details">
                            <div><strong>Status:</strong> ${result.status}</div>
                            <div><strong>Duration:</strong> ${duration}ms</div>
                            ${result.error ? ` + "`" + `<div><strong>Error:</strong> ${result.error}</div>` + "`" + ` : ''}
                            ${outputPreview ? ` + "`" + `<div class="output-preview">${outputPreview}</div>` + "`" + ` : ''}
                        </div>
                    </div>
                ` + "`" + `;
            }).join('');
        }
        
        function formatDuration(nanoseconds) {
            const ms = Math.round(nanoseconds / 1000000);
            if (ms < 1000) return ms + 'ms';
            return Math.round(ms / 1000) + 's';
        }
        
        // Initialize
        connectWebSocket();
        refreshData();
        
        // Refresh data every 30 seconds
        setInterval(refreshData, 30000);
    </script>
</body>
</html>`

	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(html))
}

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
