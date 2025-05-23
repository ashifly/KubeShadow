package logger

import (
	"fmt"
	"os"
	"time"
)

type LogLevel int

const (
	DEBUG LogLevel = iota
	INFO
	WARN
	ERROR
)

var (
	currentLevel = INFO
	levelNames   = map[LogLevel]string{
		DEBUG: "DEBUG",
		INFO:  "INFO",
		WARN:  "WARN",
		ERROR: "ERROR",
	}
)

// SetLevel sets the current logging level
func SetLevel(level LogLevel) {
	currentLevel = level
}

// SetLogLevel sets the current logging level.
func SetLogLevel(level LogLevel) {
	currentLevel = level
}

// log prints a message with the given level
func log(level LogLevel, format string, args ...interface{}) {
	if level < currentLevel {
		return
	}

	timestamp := time.Now().Format("2006-01-02 15:04:05")
	message := fmt.Sprintf(format, args...)
	fmt.Fprintf(os.Stderr, "[%s] %s: %s\n", timestamp, levelNames[level], message)
}

// Debug logs a debug message
func Debug(format string, args ...interface{}) {
	log(DEBUG, format, args...)
}

// Info logs an info message
func Info(format string, args ...interface{}) {
	log(INFO, format, args...)
}

// Warn logs a warning message
func Warn(format string, args ...interface{}) {
	log(WARN, format, args...)
}

// Error logs an error message
func Error(format string, args ...interface{}) {
	log(ERROR, format, args...)
}
