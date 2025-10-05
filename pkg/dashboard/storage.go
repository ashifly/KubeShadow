package dashboard

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// Storage manages persistent storage for dashboard data
type Storage struct {
	db *sql.DB
}

// NewStorage creates a new storage instance with SQLite database
func NewStorage(dbPath string) (*Storage, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	storage := &Storage{db: db}
	if err := storage.initTables(); err != nil {
		return nil, fmt.Errorf("failed to initialize tables: %w", err)
	}

	return storage, nil
}

// initTables creates the necessary database tables
func (s *Storage) initTables() error {
	commandsTable := `
	CREATE TABLE IF NOT EXISTS commands (
		id TEXT PRIMARY KEY,
		module TEXT NOT NULL,
		command TEXT NOT NULL,
		arguments TEXT,
		flags TEXT,
		status TEXT NOT NULL,
		start_time DATETIME NOT NULL,
		end_time DATETIME,
		duration INTEGER,
		exit_code INTEGER,
		metadata TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);`

	commandResultsTable := `
	CREATE TABLE IF NOT EXISTS command_results (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		command_id TEXT NOT NULL,
		output TEXT,
		error_msg TEXT,
		findings TEXT,
		summary TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (command_id) REFERENCES commands (id)
	);`

	graphNodesTable := `
	CREATE TABLE IF NOT EXISTS graph_nodes (
		id TEXT PRIMARY KEY,
		node_type TEXT NOT NULL,
		name TEXT NOT NULL,
		namespace TEXT,
		metadata TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);`

	graphEdgesTable := `
	CREATE TABLE IF NOT EXISTS graph_edges (
		id TEXT PRIMARY KEY,
		source_id TEXT NOT NULL,
		target_id TEXT NOT NULL,
		edge_type TEXT NOT NULL,
		weight REAL,
		metadata TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (source_id) REFERENCES graph_nodes (id),
		FOREIGN KEY (target_id) REFERENCES graph_nodes (id)
	);`

	graphDeltasTable := `
	CREATE TABLE IF NOT EXISTS graph_deltas (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		command_id TEXT NOT NULL,
		delta_type TEXT NOT NULL,
		nodes TEXT,
		edges TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (command_id) REFERENCES commands (id)
	);`

	tables := []string{commandsTable, commandResultsTable, graphNodesTable, graphEdgesTable, graphDeltasTable}
	
	for _, table := range tables {
		if _, err := s.db.Exec(table); err != nil {
			return fmt.Errorf("failed to create table: %w", err)
		}
	}

	return nil
}

// StoreCommand stores a command execution record
func (s *Storage) StoreCommand(cmd *CommandResult) error {
	argsJSON, _ := json.Marshal(cmd.Arguments)
	flagsJSON, _ := json.Marshal(cmd.Flags)
	metadataJSON, _ := json.Marshal(cmd.Metadata)

	var endTime *time.Time
	if cmd.EndTime != nil {
		endTime = cmd.EndTime
	}

	query := `
	INSERT OR REPLACE INTO commands 
	(id, module, command, arguments, flags, status, start_time, end_time, duration, exit_code, metadata)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	_, err := s.db.Exec(query,
		cmd.ID, cmd.Module, cmd.Command, string(argsJSON), string(flagsJSON),
		cmd.Status, cmd.StartTime, endTime, cmd.Duration.Nanoseconds(), cmd.ExitCode, string(metadataJSON))

	return err
}

// StoreCommandResult stores detailed command output and findings
func (s *Storage) StoreCommandResult(commandID string, output, errorMsg string, findings []Finding, summary ModuleSummary) error {
	findingsJSON, _ := json.Marshal(findings)
	summaryJSON, _ := json.Marshal(summary)

	query := `
	INSERT INTO command_results 
	(command_id, output, error_msg, findings, summary)
	VALUES (?, ?, ?, ?, ?)`

	_, err := s.db.Exec(query, commandID, output, errorMsg, string(findingsJSON), string(summaryJSON))
	return err
}

// GetCommand retrieves a command by ID
func (s *Storage) GetCommand(id string) (*CommandResult, error) {
	query := `
	SELECT id, module, command, arguments, flags, status, start_time, end_time, duration, exit_code, metadata
	FROM commands WHERE id = ?`

	row := s.db.QueryRow(query, id)
	
	var cmd CommandResult
	var argsJSON, flagsJSON, metadataJSON string
	var endTime *time.Time
	var duration int64

	err := row.Scan(&cmd.ID, &cmd.Module, &cmd.Command, &argsJSON, &flagsJSON,
		&cmd.Status, &cmd.StartTime, &endTime, &duration, &cmd.ExitCode, &metadataJSON)

	if err != nil {
		return nil, err
	}

	// Parse JSON fields
	json.Unmarshal([]byte(argsJSON), &cmd.Arguments)
	json.Unmarshal([]byte(flagsJSON), &cmd.Flags)
	json.Unmarshal([]byte(metadataJSON), &cmd.Metadata)

	cmd.EndTime = endTime
	cmd.Duration = time.Duration(duration)

	return &cmd, nil
}

// GetCommands retrieves all commands with pagination
func (s *Storage) GetCommands(limit, offset int) ([]*CommandResult, error) {
	query := `
	SELECT id, module, command, arguments, flags, status, start_time, end_time, duration, exit_code, metadata
	FROM commands 
	ORDER BY start_time DESC 
	LIMIT ? OFFSET ?`

	rows, err := s.db.Query(query, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var commands []*CommandResult
	for rows.Next() {
		var cmd CommandResult
		var argsJSON, flagsJSON, metadataJSON string
		var endTime *time.Time
		var duration int64

		err := rows.Scan(&cmd.ID, &cmd.Module, &cmd.Command, &argsJSON, &flagsJSON,
			&cmd.Status, &cmd.StartTime, &endTime, &duration, &cmd.ExitCode, &metadataJSON)

		if err != nil {
			continue
		}

		// Parse JSON fields
		json.Unmarshal([]byte(argsJSON), &cmd.Arguments)
		json.Unmarshal([]byte(flagsJSON), &cmd.Flags)
		json.Unmarshal([]byte(metadataJSON), &cmd.Metadata)

		cmd.EndTime = endTime
		cmd.Duration = time.Duration(duration)

		commands = append(commands, &cmd)
	}

	return commands, nil
}

// GetCommandResult retrieves detailed results for a command
func (s *Storage) GetCommandResult(commandID string) (*CommandResult, []Finding, ModuleSummary, error) {
	// Get command
	cmd, err := s.GetCommand(commandID)
	if err != nil {
		return nil, nil, ModuleSummary{}, err
	}

	// Get detailed results
	query := `
	SELECT output, error_msg, findings, summary
	FROM command_results 
	WHERE command_id = ? 
	ORDER BY created_at DESC 
	LIMIT 1`

	row := s.db.QueryRow(query, commandID)
	
	var output, errorMsg, findingsJSON, summaryJSON string
	err = row.Scan(&output, &errorMsg, &findingsJSON, &summaryJSON)
	if err != nil {
		return cmd, nil, ModuleSummary{}, err
	}

	// Parse findings and summary
	var findings []Finding
	var summary ModuleSummary
	
	json.Unmarshal([]byte(findingsJSON), &findings)
	json.Unmarshal([]byte(summaryJSON), &summary)

	cmd.Output = output
	cmd.ErrorMsg = errorMsg

	return cmd, findings, summary, nil
}

// StoreGraphDelta stores a graph delta for a command
func (s *Storage) StoreGraphDelta(commandID, deltaType string, nodes []GraphNode, edges []GraphEdge) error {
	nodesJSON, _ := json.Marshal(nodes)
	edgesJSON, _ := json.Marshal(edges)

	query := `
	INSERT INTO graph_deltas 
	(command_id, delta_type, nodes, edges)
	VALUES (?, ?, ?, ?)`

	_, err := s.db.Exec(query, commandID, deltaType, string(nodesJSON), string(edgesJSON))
	return err
}

// GetGraphDeltas retrieves graph deltas for a command
func (s *Storage) GetGraphDeltas(commandID string) ([]GraphDelta, error) {
	query := `
	SELECT id, command_id, delta_type, nodes, edges, created_at
	FROM graph_deltas 
	WHERE command_id = ?
	ORDER BY created_at ASC`

	rows, err := s.db.Query(query, commandID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var deltas []GraphDelta
	for rows.Next() {
		var delta GraphDelta
		var nodesJSON, edgesJSON string

		err := rows.Scan(&delta.ID, &delta.CommandID, &delta.Type, &nodesJSON, &edgesJSON, &delta.CreatedAt)
		if err != nil {
			continue
		}

		json.Unmarshal([]byte(nodesJSON), &delta.Nodes)
		json.Unmarshal([]byte(edgesJSON), &delta.Edges)

		deltas = append(deltas, delta)
	}

	return deltas, nil
}

// GetFullGraph retrieves the complete attack graph
func (s *Storage) GetFullGraph() (*AttackGraph, error) {
	// Get all nodes
	nodesQuery := `SELECT id, node_type, name, namespace, metadata FROM graph_nodes`
	rows, err := s.db.Query(nodesQuery)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var nodes []GraphNode
	for rows.Next() {
		var node GraphNode
		var metadataJSON string

		err := rows.Scan(&node.ID, &node.Type, &node.Name, &node.Namespace, &metadataJSON)
		if err != nil {
			continue
		}

		json.Unmarshal([]byte(metadataJSON), &node.Metadata)
		nodes = append(nodes, node)
	}

	// Get all edges
	edgesQuery := `SELECT id, source_id, target_id, edge_type, weight, metadata FROM graph_edges`
	rows, err = s.db.Query(edgesQuery)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var edges []GraphEdge
	for rows.Next() {
		var edge GraphEdge
		var metadataJSON string

		err := rows.Scan(&edge.ID, &edge.SourceID, &edge.TargetID, &edge.Type, &edge.Weight, &metadataJSON)
		if err != nil {
			continue
		}

		json.Unmarshal([]byte(metadataJSON), &edge.Metadata)
		edges = append(edges, edge)
	}

	return &AttackGraph{
		Nodes: nodes,
		Edges: edges,
	}, nil
}

// Close closes the database connection
func (s *Storage) Close() error {
	return s.db.Close()
}
