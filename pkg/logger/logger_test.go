package logger

import (
	"os"
	"strings"
	"testing"
)

func TestLogger(t *testing.T) {
	// Save original stderr
	origStderr := os.Stderr
	defer func() { os.Stderr = origStderr }()

	// Create a temp file to capture logs
	tmpfile, err := os.CreateTemp("", "logtest")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpfile.Name())
	os.Stderr = tmpfile

	tests := []struct {
		name     string
		level    string
		msg      string
		args     []interface{}
		logFunc  func(string, ...interface{})
		contains []string
	}{
		{
			name:     "Debug message",
			level:    "DEBUG",
			msg:      "debug message %s",
			args:     []interface{}{"test"},
			logFunc:  Debug,
			contains: []string{"DEBUG", "debug message test"},
		},
		{
			name:     "Info message",
			level:    "INFO",
			msg:      "info message %d",
			args:     []interface{}{42},
			logFunc:  Info,
			contains: []string{"INFO", "info message 42"},
		},
		{
			name:     "Warn message",
			level:    "WARN",
			msg:      "warn message %v",
			args:     []interface{}{true},
			logFunc:  Warn,
			contains: []string{"WARN", "warn message true"},
		},
		{
			name:     "Error message",
			level:    "ERROR",
			msg:      "error message %q",
			args:     []interface{}{"test"},
			logFunc:  Error,
			contains: []string{"ERROR", "error message \"test\""},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpfile.Truncate(0)
			tmpfile.Seek(0, 0)
			SetLogLevel(DEBUG)
			tt.logFunc(tt.msg, tt.args...)
			os.Stderr.Sync()
			content, _ := os.ReadFile(tmpfile.Name())
			for _, str := range tt.contains {
				if !strings.Contains(string(content), str) {
					t.Errorf("Expected log to contain %q, got %q", str, string(content))
				}
			}
		})
	}
}

func TestLogLevelFiltering(t *testing.T) {
	origStderr := os.Stderr
	defer func() { os.Stderr = origStderr }()

	tmpfile, err := os.CreateTemp("", "logtest")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpfile.Name())
	os.Stderr = tmpfile

	tests := []struct {
		name     string
		level    LogLevel
		messages []struct {
			level LogLevel
			msg   string
		}
		expected   []string
		unexpected []string
	}{
		{
			name:  "Info level filtering",
			level: INFO,
			messages: []struct {
				level LogLevel
				msg   string
			}{
				{DEBUG, "debug message"},
				{INFO, "info message"},
				{WARN, "warn message"},
				{ERROR, "error message"},
			},
			expected:   []string{"info message", "warn message", "error message"},
			unexpected: []string{"debug message"},
		},
		{
			name:  "Warn level filtering",
			level: WARN,
			messages: []struct {
				level LogLevel
				msg   string
			}{
				{DEBUG, "debug message"},
				{INFO, "info message"},
				{WARN, "warn message"},
				{ERROR, "error message"},
			},
			expected:   []string{"warn message", "error message"},
			unexpected: []string{"debug message", "info message"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpfile.Truncate(0)
			tmpfile.Seek(0, 0)
			SetLogLevel(tt.level)

			for _, msg := range tt.messages {
				switch msg.level {
				case DEBUG:
					Debug("%s", msg.msg)
				case INFO:
					Info("%s", msg.msg)
				case WARN:
					Warn("%s", msg.msg)
				case ERROR:
					Error("%s", msg.msg)
				}
			}

			os.Stderr.Sync()
			content, _ := os.ReadFile(tmpfile.Name())

			for _, str := range tt.expected {
				if !strings.Contains(string(content), str) {
					t.Errorf("Expected log to contain %q, got %q", str, string(content))
				}
			}

			for _, str := range tt.unexpected {
				if strings.Contains(string(content), str) {
					t.Errorf("Expected log to not contain %q, got %q", str, string(content))
				}
			}
		})
	}
}
