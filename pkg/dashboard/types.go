package dashboard

import "time"

// CommandResult represents the result of a KubeShadow command execution
type CommandResult struct {
	ID          string                 `json:"id"`
	Command     string                 `json:"command"`
	Module      string                 `json:"module"`
	Arguments   []string               `json:"arguments"`
	Flags       map[string]interface{} `json:"flags"`
	Status      string                 `json:"status"` // "running", "completed", "error"
	StartTime   time.Time              `json:"startTime"`
	EndTime     *time.Time             `json:"endTime,omitempty"`
	Duration    time.Duration          `json:"duration"`
	Output      string                 `json:"output"`
	ErrorMsg    string                 `json:"error,omitempty"`
	ExitCode    int                    `json:"exitCode"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// DashboardStats represents overall dashboard statistics
type DashboardStats struct {
	TotalCommands    int           `json:"totalCommands"`
	SuccessfulRuns   int           `json:"successfulRuns"`
	FailedRuns       int           `json:"failedRuns"`
	RunningCommands  int           `json:"runningCommands"`
	AverageTime      time.Duration `json:"averageTime"`
	LastExecution    *time.Time    `json:"lastExecution,omitempty"`
	UptimeStart      time.Time     `json:"uptimeStart"`
}

// WebSocketMessage represents messages sent via WebSocket
type WebSocketMessage struct {
	Type string      `json:"type"` // "result", "status", "stats"
	Data interface{} `json:"data"`
}
