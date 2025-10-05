package dashboard

import (
	"html/template"
	"log"
	"net/http"
	"os"
)

// FrontendManager manages the enhanced frontend with attack-map visualization
type FrontendManager struct {
	templates *template.Template
}

// NewFrontendManager creates a new frontend manager
func NewFrontendManager() *FrontendManager {
	tmpl := template.New("dashboard")
	
	// Load the enhanced dashboard template
	tmpl = template.Must(tmpl.Parse(enhancedDashboardHTML))
	
	return &FrontendManager{
		templates: tmpl,
	}
}

// ServeEnhancedDashboard serves the enhanced dashboard with attack-map
func (fm *FrontendManager) ServeEnhancedDashboard(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	
	// Check if logo exists
	logoExists := false
	if _, err := os.Stat("logo.png"); err == nil {
		logoExists = true
	}
	
	data := map[string]interface{}{
		"LogoExists": logoExists,
		"Title":      "KubeShadow Enhanced Dashboard",
		"Version":    "2.0.0",
	}

	if err := fm.templates.Execute(w, data); err != nil {
		log.Printf("Error executing template: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// enhancedDashboardHTML contains the enhanced dashboard HTML with attack-map visualization
const enhancedDashboardHTML = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{.Title}}</title>
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
            max-width: 1400px;
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
        
        .tabs {
            display: flex;
            background: rgba(255, 255, 255, 0.1);
            border-radius: 10px;
            padding: 5px;
            margin-bottom: 20px;
            backdrop-filter: blur(10px);
        }
        
        .tab {
            flex: 1;
            padding: 15px;
            text-align: center;
            color: white;
            cursor: pointer;
            border-radius: 8px;
            transition: all 0.3s ease;
            font-weight: 500;
        }
        
        .tab.active {
            background: rgba(255, 255, 255, 0.2);
            box-shadow: 0 2px 8px rgba(0,0,0,0.2);
        }
        
        .tab:hover {
            background: rgba(255, 255, 255, 0.15);
        }
        
        .tab-content {
            display: none;
        }
        
        .tab-content.active {
            display: block;
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
        
        .attack-map-container {
            background: rgba(255, 255, 255, 0.95);
            border-radius: 10px;
            padding: 20px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            backdrop-filter: blur(10px);
            margin-bottom: 20px;
        }
        
        .attack-map-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
        }
        
        .attack-map-header h2 {
            color: #667eea;
        }
        
        .map-controls {
            display: flex;
            gap: 10px;
            align-items: center;
        }
        
        .control-btn {
            border: none;
            padding: 8px 16px;
            border-radius: 5px;
            cursor: pointer;
            transition: all 0.3s ease;
            font-weight: 500;
            font-size: 0.9rem;
        }
        
        .filter-btn {
            background: #667eea;
            color: white;
        }
        
        .filter-btn:hover {
            background: #5a6fd8;
        }
        
        .export-btn {
            background: #28a745;
            color: white;
        }
        
        .export-btn:hover {
            background: #218838;
        }
        
        .timeline-btn {
            background: #ffc107;
            color: #333;
        }
        
        .timeline-btn:hover {
            background: #e0a800;
        }
        
        #attack-map {
            width: 100%;
            height: 600px;
            border: 1px solid #e0e0e0;
            border-radius: 8px;
            background: #f8f9fa;
        }
        
        .command-results {
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
        
        .expandable-output {
            display: none;
            background: #f8f9fa;
            padding: 15px;
            border-radius: 4px;
            margin-top: 10px;
            font-family: 'Courier New', monospace;
            font-size: 0.9rem;
            max-height: 300px;
            overflow-y: auto;
            white-space: pre-wrap;
            border: 1px solid #e0e0e0;
        }
        
        .expand-btn {
            background: #667eea;
            color: white;
            border: none;
            padding: 5px 10px;
            border-radius: 3px;
            cursor: pointer;
            font-size: 0.8rem;
            margin-top: 5px;
        }
        
        .expand-btn:hover {
            background: #5a6fd8;
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
        
        .filter-panel {
            display: none;
            background: rgba(255, 255, 255, 0.95);
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
            backdrop-filter: blur(10px);
        }
        
        .filter-panel.active {
            display: block;
        }
        
        .filter-group {
            margin-bottom: 15px;
        }
        
        .filter-group label {
            display: block;
            margin-bottom: 5px;
            font-weight: 500;
            color: #333;
        }
        
        .filter-group select,
        .filter-group input {
            width: 100%;
            padding: 8px;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-size: 0.9rem;
        }
        
        .filter-actions {
            display: flex;
            gap: 10px;
            margin-top: 15px;
        }
        
        .apply-filter {
            background: #28a745;
            color: white;
            border: none;
            padding: 8px 16px;
            border-radius: 4px;
            cursor: pointer;
        }
        
        .clear-filter {
            background: #6c757d;
            color: white;
            border: none;
            padding: 8px 16px;
            border-radius: 4px;
            cursor: pointer;
        }
        
        .loading {
            text-align: center;
            padding: 40px;
            color: #666;
        }
        
        .spinner {
            border: 4px solid #f3f3f3;
            border-top: 4px solid #667eea;
            border-radius: 50%;
            width: 40px;
            height: 40px;
            animation: spin 1s linear infinite;
            margin: 0 auto 20px;
        }
        
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        
        .alert {
            padding: 15px;
            margin-bottom: 20px;
            border-radius: 8px;
            font-weight: 500;
        }
        
        .alert-danger {
            background: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
        }
        
        .alert-warning {
            background: #fff3cd;
            color: #856404;
            border: 1px solid #ffeaa7;
        }
        
        .alert-info {
            background: #d1ecf1;
            color: #0c5460;
            border: 1px solid #bee5eb;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            {{if .LogoExists}}
            <img src="/logo.png" alt="KubeShadow Logo" class="logo">
            {{end}}
            <h1>{{.Title}}</h1>
            <p>Real-time security testing with advanced attack-map visualization</p>
        </div>
        
        <div class="tabs">
            <div class="tab active" onclick="switchTab('overview')">📊 Overview</div>
            <div class="tab" onclick="switchTab('attack-map')">🗺️ Attack Map</div>
            <div class="tab" onclick="switchTab('commands')">⚡ Commands</div>
            <div class="tab" onclick="switchTab('chains')">🔗 Attack Chains</div>
        </div>
        
        <!-- Overview Tab -->
        <div id="overview" class="tab-content active">
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
                <div class="stat-card">
                    <h3>Attack Nodes</h3>
                    <div class="value" id="attack-nodes">0</div>
                </div>
                <div class="stat-card">
                    <h3>Attack Edges</h3>
                    <div class="value" id="attack-edges">0</div>
                </div>
                <div class="stat-card">
                    <h3>High Risk</h3>
                    <div class="value" id="high-risk">0</div>
                </div>
            </div>
        </div>
        
        <!-- Attack Map Tab -->
        <div id="attack-map" class="tab-content">
            <div class="attack-map-container">
                <div class="attack-map-header">
                    <h2>🗺️ Attack Map</h2>
                    <div class="map-controls">
                        <button class="control-btn filter-btn" onclick="toggleFilter()">🔍 Filter</button>
                        <button class="control-btn export-btn" onclick="exportGraph()">📤 Export</button>
                        <button class="control-btn timeline-btn" onclick="toggleTimeline()">⏱️ Timeline</button>
                    </div>
                </div>
                
                <div class="filter-panel" id="filter-panel">
                    <div class="filter-group">
                        <label>Node Types:</label>
                        <select id="node-types" multiple>
                            <option value="pod">Pods</option>
                            <option value="service">Services</option>
                            <option value="secret">Secrets</option>
                            <option value="service-account">Service Accounts</option>
                            <option value="role">Roles</option>
                            <option value="user">Users</option>
                        </select>
                    </div>
                    <div class="filter-group">
                        <label>Edge Types:</label>
                        <select id="edge-types" multiple>
                            <option value="privilege-escalation">Privilege Escalation</option>
                            <option value="rbac">RBAC</option>
                            <option value="network">Network</option>
                            <option value="access">Access</option>
                        </select>
                    </div>
                    <div class="filter-group">
                        <label>Namespaces:</label>
                        <select id="namespaces" multiple>
                            <option value="default">default</option>
                            <option value="kube-system">kube-system</option>
                        </select>
                    </div>
                    <div class="filter-actions">
                        <button class="apply-filter" onclick="applyFilter()">Apply Filter</button>
                        <button class="clear-filter" onclick="clearFilter()">Clear Filter</button>
                    </div>
                </div>
                
                <div id="attack-map" style="width: 100%; height: 600px; border: 1px solid #e0e0e0; border-radius: 8px; background: #f8f9fa;"></div>
            </div>
        </div>
        
        <!-- Commands Tab -->
        <div id="commands" class="tab-content">
            <div class="command-results">
                <div class="results-header">
                    <h2>⚡ Command Results</h2>
                    <div class="header-buttons">
                        <button class="export-btn" onclick="downloadCSV()">📊 Export CSV</button>
                        <button class="export-btn" onclick="downloadPDF()">📄 Export PDF</button>
                        <button class="control-btn" onclick="refreshData()">🔄 Refresh</button>
                    </div>
                </div>
                <div id="results-container">
                    <div class="loading">
                        <div class="spinner"></div>
                        Loading command results...
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Attack Chains Tab -->
        <div id="chains" class="tab-content">
            <div class="command-results">
                <div class="results-header">
                    <h2>🔗 Attack Chains</h2>
                    <div class="header-buttons">
                        <button class="export-btn" onclick="exportChains()">📤 Export Chains</button>
                        <button class="control-btn" onclick="refreshChains()">🔄 Refresh</button>
                    </div>
                </div>
                <div id="chains-container">
                    <div class="loading">
                        <div class="spinner"></div>
                        Analyzing attack chains...
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <div id="connection-status" class="connection-status disconnected">
        Disconnected
    </div>
    
    <script>
        // Global variables
        let ws;
        let connectionStatus = document.getElementById('connection-status');
        let currentGraph = null;
        let currentFilter = {};
        
        // Initialize dashboard
        function initDashboard() {
            connectWebSocket();
            refreshData();
            loadAttackMap();
        }
        
        // WebSocket connection
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
        
        // Handle WebSocket messages
        function handleWebSocketMessage(message) {
            switch(message.type) {
                case 'graph_delta':
                    handleGraphDelta(message.data);
                    break;
                case 'chain_found':
                    handleAttackChain(message.data);
                    break;
                case 'command_finished':
                    handleCommandFinished(message.data);
                    break;
                case 'stats_update':
                    handleStatsUpdate(message.data);
                    break;
                case 'graph_initial':
                    currentGraph = message.data;
                    updateAttackMap();
                    break;
                case 'commands_initial':
                    updateCommands(message.data);
                    break;
                case 'stats_initial':
                    updateStats(message.data);
                    break;
            }
        }
        
        // Tab switching
        function switchTab(tabName) {
            // Hide all tab contents
            document.querySelectorAll('.tab-content').forEach(tab => {
                tab.classList.remove('active');
            });
            
            // Remove active class from all tabs
            document.querySelectorAll('.tab').forEach(tab => {
                tab.classList.remove('active');
            });
            
            // Show selected tab
            document.getElementById(tabName).classList.add('active');
            
            // Add active class to clicked tab
            event.target.classList.add('active');
            
            // Load content for specific tabs
            if (tabName === 'attack-map') {
                loadAttackMap();
            } else if (tabName === 'chains') {
                loadAttackChains();
            }
        }
        
        // Attack map functions
        function loadAttackMap() {
            fetch('/api/v1/graph')
                .then(response => response.json())
                .then(graph => {
                    currentGraph = graph;
                    updateAttackMap();
                })
                .catch(err => {
                    console.error('Error loading attack map:', err);
                    document.getElementById('attack-map').innerHTML = 
                        '<div class="alert alert-danger">Failed to load attack map</div>';
                });
        }
        
        function updateAttackMap() {
            if (!currentGraph) return;
            
            // Simple visualization - in a real implementation, this would use Cytoscape.js or vis.js
            const container = document.getElementById('attack-map');
            container.innerHTML = '<div class="loading"><div class="spinner"></div>Rendering attack map...</div>';
            
            // Simulate rendering
            setTimeout(() => {
                const nodeCount = currentGraph.nodes ? currentGraph.nodes.length : 0;
                const edgeCount = currentGraph.edges ? currentGraph.edges.length : 0;
                container.innerHTML = 
                    '<div style="padding: 20px; text-align: center;">' +
                        '<h3>Attack Map Visualization</h3>' +
                        '<p>Nodes: ' + nodeCount + '</p>' +
                        '<p>Edges: ' + edgeCount + '</p>' +
                        '<p><em>Advanced visualization would be implemented here using Cytoscape.js or vis.js</em></p>' +
                    '</div>';
            }, 1000);
        }
        
        function toggleFilter() {
            const panel = document.getElementById('filter-panel');
            panel.classList.toggle('active');
        }
        
        function applyFilter() {
            const nodeTypes = Array.from(document.getElementById('node-types').selectedOptions).map(o => o.value);
            const edgeTypes = Array.from(document.getElementById('edge-types').selectedOptions).map(o => o.value);
            const namespaces = Array.from(document.getElementById('namespaces').selectedOptions).map(o => o.value);
            
            currentFilter = { nodeTypes, edgeTypes, namespaces };
            
            // Send filter request via WebSocket
            if (ws && ws.readyState === WebSocket.OPEN) {
                ws.send(JSON.stringify({
                    type: 'filter',
                    nodeTypes: nodeTypes,
                    edgeTypes: edgeTypes,
                    namespaces: namespaces
                }));
            }
        }
        
        function clearFilter() {
            document.getElementById('node-types').selectedIndex = -1;
            document.getElementById('edge-types').selectedIndex = -1;
            document.getElementById('namespaces').selectedIndex = -1;
            currentFilter = {};
            loadAttackMap();
        }
        
        function exportGraph() {
            const format = prompt('Export format (json/csv/dot/mermaid):', 'json');
            if (format) {
                window.open('/api/v1/export/graph?format=' + format, '_blank');
            }
        }
        
        function toggleTimeline() {
            alert('Timeline feature would be implemented here');
        }
        
        // Command functions
        function refreshData() {
            Promise.all([
                fetch('/api/v1/commands').then(r => r.json()),
                fetch('/api/v1/graph/stats').then(r => r.json())
            ]).then(([commands, stats]) => {
                updateStats(stats);
                updateCommands(commands.commands || commands);
            }).catch(err => {
                console.error('Error fetching data:', err);
            });
        }
        
        function updateCommands(commands) {
            const container = document.getElementById('results-container');
            
            if (!commands || commands.length === 0) {
                container.innerHTML = '<div class="no-results">No command results yet. Run a KubeShadow command with the --dashboard flag to see results here.</div>';
                return;
            }
            
            // Sort results by start time (newest first)
            commands.sort((a, b) => new Date(b.startTime) - new Date(a.startTime));
            
            container.innerHTML = commands.map(command => {
                const startTime = new Date(command.startTime);
                const duration = command.duration ? Math.round(command.duration / 1000000) : 0;
                const outputPreview = command.output ? command.output.substring(0, 200) + (command.output.length > 200 ? '...' : '') : '';
                
                const errorDiv = command.error ? '<div><strong>Error:</strong> ' + command.error + '</div>' : '';
                const outputSection = outputPreview ? 
                    '<div class="output-preview">' + outputPreview + '</div>' +
                    '<button class="expand-btn" onclick="toggleOutput(\'' + command.id + '\')">Show Full Output</button>' +
                    '<div class="expandable-output" id="output-' + command.id + '">' + (command.output || '') + '</div>' : '';
                
                return '<div class="result-card">' +
                    '<div class="result-header">' +
                        '<div class="command-name">' +
                            '<span class="status-indicator status-' + command.status + '"></span>' +
                            command.module + ': ' + command.command +
                        '</div>' +
                        '<div class="timestamp">' + startTime.toLocaleString() + '</div>' +
                    '</div>' +
                    '<div class="result-details">' +
                        '<div><strong>Status:</strong> ' + command.status + '</div>' +
                        '<div><strong>Duration:</strong> ' + duration + 'ms</div>' +
                        errorDiv +
                        outputSection +
                    '</div>' +
                '</div>';
            }).join('');
        }
        
        function toggleOutput(commandId) {
            const output = document.getElementById('output-' + commandId);
            const btn = event.target;
            
            if (output.style.display === 'none' || output.style.display === '') {
                output.style.display = 'block';
                btn.textContent = 'Hide Output';
            } else {
                output.style.display = 'none';
                btn.textContent = 'Show Full Output';
            }
        }
        
        // Attack chain functions
        function loadAttackChains() {
            fetch('/api/v1/graph/chains')
                .then(response => response.json())
                .then(data => {
                    updateAttackChains(data.chains || []);
                })
                .catch(err => {
                    console.error('Error loading attack chains:', err);
                    document.getElementById('chains-container').innerHTML = 
                        '<div class="alert alert-danger">Failed to load attack chains</div>';
                });
        }
        
        function updateAttackChains(chains) {
            const container = document.getElementById('chains-container');
            
            if (chains.length === 0) {
                container.innerHTML = '<div class="no-results">No attack chains found yet. Run more security tests to discover potential attack paths.</div>';
                return;
            }
            
            container.innerHTML = chains.map(chain => {
                const stepsHtml = chain.steps.map(step => 
                    '<div style="margin-left: 20px; margin-top: 5px;">' +
                        '<strong>' + step.from + '</strong> → <strong>' + step.to + '</strong>' +
                        '<br><small>' + step.action + ' (Risk: ' + step.risk.toFixed(1) + ')</small>' +
                    '</div>'
                ).join('');
                
                return '<div class="result-card">' +
                    '<div class="result-header">' +
                        '<div class="command-name">' +
                            '🔗 Attack Chain (Risk: ' + chain.riskScore.toFixed(1) + ')' +
                        '</div>' +
                        '<div class="timestamp">' + new Date(chain.lastUpdated).toLocaleString() + '</div>' +
                    '</div>' +
                    '<div class="result-details">' +
                        '<div><strong>Source:</strong> ' + chain.source + '</div>' +
                        '<div><strong>Target:</strong> ' + chain.target + '</div>' +
                        '<div><strong>Confidence:</strong> ' + (chain.confidence * 100).toFixed(1) + '%</div>' +
                        '<div><strong>Steps:</strong> ' + chain.steps.length + '</div>' +
                        stepsHtml +
                    '</div>' +
                '</div>';
            }).join('');
        }
        
        function refreshChains() {
            loadAttackChains();
        }
        
        function exportChains() {
            window.open('/api/v1/export/graph?format=json', '_blank');
        }
        
        // Stats functions
        function updateStats(stats) {
            document.getElementById('total-commands').textContent = stats.totalCommands || 0;
            document.getElementById('successful-runs').textContent = stats.successfulRuns || 0;
            document.getElementById('failed-runs').textContent = stats.failedRuns || 0;
            document.getElementById('running-commands').textContent = stats.runningCommands || 0;
            
            if (stats.averageTime) {
                const avgMs = Math.round(stats.averageTime / 1000000);
                document.getElementById('avg-duration').textContent = avgMs + 'ms';
            }
            
            // Update attack map stats
            document.getElementById('attack-nodes').textContent = stats.totalNodes || 0;
            document.getElementById('attack-edges').textContent = stats.totalEdges || 0;
            document.getElementById('high-risk').textContent = stats.highRiskNodes || 0;
        }
        
        // WebSocket message handlers
        function handleGraphDelta(data) {
            console.log('Graph delta received:', data);
            // Update attack map with new data
            loadAttackMap();
        }
        
        function handleAttackChain(data) {
            console.log('Attack chain found:', data);
            if (data.alert) {
                alert('🚨 High-risk attack chain detected!');
            }
            // Update chains tab if it's active
            if (document.getElementById('chains').classList.contains('active')) {
                loadAttackChains();
            }
        }
        
        function handleCommandFinished(data) {
            console.log('Command finished:', data);
            // Update commands tab
            if (document.getElementById('commands').classList.contains('active')) {
                refreshData();
            }
        }
        
        function handleStatsUpdate(data) {
            updateStats(data);
        }
        
        // Export functions
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
                    a.download = 'kubeshadow-results-' + new Date().toISOString().split('T')[0] + '.csv';
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
            const pdfBtn = document.querySelector('.pdf-btn');
            const originalText = pdfBtn ? pdfBtn.textContent : '📄 Export PDF';
            if (pdfBtn) {
                pdfBtn.textContent = '📄 Generating...';
                pdfBtn.disabled = true;
            }
            
            fetch('/api/export/pdf')
                .then(response => {
                    if (!response.ok) throw new Error('Failed to export PDF');
                    return response.blob();
                })
                .then(blob => {
                    const url = window.URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = 'kubeshadow-dashboard-' + new Date().toISOString().split('T')[0] + '.pdf';
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
                    if (pdfBtn) {
                        pdfBtn.textContent = originalText;
                        pdfBtn.disabled = false;
                    }
                });
        }
        
        // Initialize dashboard when page loads
        document.addEventListener('DOMContentLoaded', initDashboard);
        
        // Refresh data every 30 seconds
        setInterval(refreshData, 30000);
    </script>
</body>
</html>
`
