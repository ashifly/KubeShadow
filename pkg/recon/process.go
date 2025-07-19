package recon

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"kubeshadow/pkg/logger"
)

// ProcessInfo represents process-related information
type ProcessInfo struct {
	PID          int
	Name         string
	User         string
	CommandLine  string
	CPU          float64
	Memory       int64
	Status       string
	ParentPID    int
	Children     []int
	Threads      int
	Priority     int
	Nice         int
	StartTime    time.Time
	Uptime       time.Duration
	WorkingDir   string
	Environment  []string
	Capabilities []string
	Limits       ProcessLimits
}

// ProcessLimits represents process resource limits
type ProcessLimits struct {
	MaxFileDescriptors    int64
	MaxProcesses          int64
	MaxStackSize          int64
	MaxCoreFileSize       int64
	MaxResidentSetSize    int64
	MaxVirtualMemory      int64
	MaxCPUTime            int64
	MaxFileSize           int64
	MaxDataSize           int64
	MaxAddressSpace       int64
	MaxLockedMemory       int64
	MaxRealTimePriority   int64
	MaxRealTimeTimeout    int64
	MaxMessageQueues      int64
	MaxPendingSignals     int64
	MaxPOSIXMessageQueues int64
}

// GetProcessInfo retrieves information about all processes
func GetProcessInfo(ctx context.Context) ([]ProcessInfo, error) {
	var processes []ProcessInfo

	// Read /proc directory
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, fmt.Errorf("failed to read /proc directory: %v", err)
	}

	for _, entry := range entries {
		// Skip non-numeric entries
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}

		// Get process details
		process, err := getProcessDetails(pid)
		if err != nil {
			logger.Warn("Failed to get details for process %d: %v", pid, err)
			continue
		}

		processes = append(processes, process)
	}

	return processes, nil
}

func getProcessDetails(pid int) (ProcessInfo, error) {
	var process ProcessInfo
	process.PID = pid

	// Get process name
	name, err := getProcessName(pid)
	if err != nil {
		return process, fmt.Errorf("failed to get process name: %v", err)
	}
	process.Name = name

	// Get process user
	user, err := getUserFromUID(pid)
	if err != nil {
		return process, fmt.Errorf("failed to get process user: %v", err)
	}
	process.User = user

	// Get command line
	cmdline, err := getCommandLine(pid)
	if err != nil {
		return process, fmt.Errorf("failed to get command line: %v", err)
	}
	process.CommandLine = cmdline

	// Get CPU and memory usage
	cpu, memory, err := getProcessStats(pid)
	if err != nil {
		return process, fmt.Errorf("failed to get process stats: %v", err)
	}
	process.CPU = cpu
	process.Memory = memory

	// Get process status
	status, err := getProcessStatus(pid)
	if err != nil {
		return process, fmt.Errorf("failed to get process status: %v", err)
	}
	process.Status = status

	// Get parent PID
	parentPID, err := getParentPID(pid)
	if err != nil {
		return process, fmt.Errorf("failed to get parent PID: %v", err)
	}
	process.ParentPID = parentPID

	// Get child processes
	children, err := getChildProcesses(pid)
	if err != nil {
		return process, fmt.Errorf("failed to get child processes: %v", err)
	}
	process.Children = children

	// Get thread count
	threads, err := getThreadCount(pid)
	if err != nil {
		return process, fmt.Errorf("failed to get thread count: %v", err)
	}
	process.Threads = threads

	// Get process priority
	priority, nice, err := getProcessPriority(pid)
	if err != nil {
		return process, fmt.Errorf("failed to get process priority: %v", err)
	}
	process.Priority = priority
	process.Nice = nice

	// Get start time
	startTime, err := getProcessStartTime(pid)
	if err != nil {
		return process, fmt.Errorf("failed to get start time: %v", err)
	}
	process.StartTime = startTime

	// Calculate uptime
	process.Uptime = time.Since(startTime)

	// Get working directory
	workingDir, err := getWorkingDir(pid)
	if err != nil {
		return process, fmt.Errorf("failed to get working directory: %v", err)
	}
	process.WorkingDir = workingDir

	// Get environment variables
	env, err := getEnvironment(pid)
	if err != nil {
		return process, fmt.Errorf("failed to get environment variables: %v", err)
	}
	process.Environment = env

	// Get capabilities
	capabilities, err := getCapabilities(pid)
	if err != nil {
		return process, fmt.Errorf("failed to get capabilities: %v", err)
	}
	process.Capabilities = capabilities

	// Get resource limits
	limits, err := getResourceLimits(pid)
	if err != nil {
		return process, fmt.Errorf("failed to get resource limits: %v", err)
	}
	process.Limits = limits

	return process, nil
}

func getProcessName(pid int) (string, error) {
	// Read /proc/<pid>/comm
	content, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "comm"))
	if err != nil {
		return "", fmt.Errorf("failed to read process name: %v", err)
	}

	return strings.TrimSpace(string(content)), nil
}

func getUserFromUID(pid int) (string, error) {
	// Read /proc/<pid>/status
	content, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "status"))
	if err != nil {
		return "", fmt.Errorf("failed to read process status: %v", err)
	}

	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		fields := strings.SplitN(line, ":", 2)
		if len(fields) != 2 {
			continue
		}

		if strings.TrimSpace(fields[0]) == "Uid" {
			uids := strings.Fields(fields[1])
			if len(uids) > 0 {
				// Read /etc/passwd
				passwd, err := os.ReadFile("/etc/passwd")
				if err != nil {
					return "", fmt.Errorf("failed to read /etc/passwd: %v", err)
				}

				lines := strings.Split(string(passwd), "\n")
				for _, line := range lines {
					fields := strings.Split(line, ":")
					if len(fields) < 3 {
						continue
					}

					if fields[2] == uids[0] {
						return fields[0], nil
					}
				}
			}
		}
	}

	return "", fmt.Errorf("user not found")
}

func getCommandLine(pid int) (string, error) {
	// Read /proc/<pid>/cmdline
	content, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "cmdline"))
	if err != nil {
		return "", fmt.Errorf("failed to read command line: %v", err)
	}

	// Replace null bytes with spaces
	cmdline := strings.ReplaceAll(string(content), "\x00", " ")
	return strings.TrimSpace(cmdline), nil
}

func getProcessStats(pid int) (float64, int64, error) {
	// Read /proc/<pid>/stat
	content, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return 0, 0, fmt.Errorf("failed to read process stats: %v", err)
	}

	fields := strings.Fields(string(content))
	if len(fields) < 24 {
		return 0, 0, fmt.Errorf("invalid process stats format")
	}

	// Parse CPU usage (utime + stime)
	utime, err := strconv.ParseInt(fields[13], 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to parse utime: %v", err)
	}

	stime, err := strconv.ParseInt(fields[14], 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to parse stime: %v", err)
	}

	// Parse memory usage (rss)
	rss, err := strconv.ParseInt(fields[23], 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to parse rss: %v", err)
	}

	// Convert CPU usage to percentage
	cpuUsage := float64(utime+stime) / float64(100) // Assuming 100Hz system clock

	// Convert memory usage to bytes
	memoryUsage := rss * 4096 // Assuming 4KB page size

	return cpuUsage, memoryUsage, nil
}

func getProcessStatus(pid int) (string, error) {
	// Read /proc/<pid>/status
	content, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "status"))
	if err != nil {
		return "", fmt.Errorf("failed to read process status: %v", err)
	}

	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		fields := strings.SplitN(line, ":", 2)
		if len(fields) != 2 {
			continue
		}

		if strings.TrimSpace(fields[0]) == "State" {
			return strings.TrimSpace(fields[1]), nil
		}
	}

	return "", fmt.Errorf("status not found")
}

func getParentPID(pid int) (int, error) {
	// Read /proc/<pid>/status
	content, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "status"))
	if err != nil {
		return 0, fmt.Errorf("failed to read process status: %v", err)
	}

	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		fields := strings.SplitN(line, ":", 2)
		if len(fields) != 2 {
			continue
		}

		if strings.TrimSpace(fields[0]) == "PPid" {
			ppid, err := strconv.Atoi(strings.TrimSpace(fields[1]))
			if err != nil {
				return 0, fmt.Errorf("failed to parse parent PID: %v", err)
			}
			return ppid, nil
		}
	}

	return 0, fmt.Errorf("parent PID not found")
}

func getChildProcesses(pid int) ([]int, error) {
	var children []int

	// Read /proc directory
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, fmt.Errorf("failed to read /proc directory: %v", err)
	}

	for _, entry := range entries {
		// Skip non-numeric entries
		childPID, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}

		// Read /proc/<pid>/status
		content, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "status"))
		if err != nil {
			continue
		}

		lines := strings.Split(string(content), "\n")
		for _, line := range lines {
			fields := strings.SplitN(line, ":", 2)
			if len(fields) != 2 {
				continue
			}

			if strings.TrimSpace(fields[0]) == "PPid" {
				ppid, err := strconv.Atoi(strings.TrimSpace(fields[1]))
				if err != nil {
					continue
				}

				if ppid == pid {
					children = append(children, childPID)
				}
				break
			}
		}
	}

	return children, nil
}

func getThreadCount(pid int) (int, error) {
	// Read /proc/<pid>/status
	content, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "status"))
	if err != nil {
		return 0, fmt.Errorf("failed to read process status: %v", err)
	}

	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		fields := strings.SplitN(line, ":", 2)
		if len(fields) != 2 {
			continue
		}

		if strings.TrimSpace(fields[0]) == "Threads" {
			threads, err := strconv.Atoi(strings.TrimSpace(fields[1]))
			if err != nil {
				return 0, fmt.Errorf("failed to parse thread count: %v", err)
			}
			return threads, nil
		}
	}

	return 0, fmt.Errorf("thread count not found")
}

func getProcessPriority(pid int) (int, int, error) {
	// Read /proc/<pid>/stat
	content, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return 0, 0, fmt.Errorf("failed to read process stats: %v", err)
	}

	fields := strings.Fields(string(content))
	if len(fields) < 20 {
		return 0, 0, fmt.Errorf("invalid process stats format")
	}

	// Parse priority
	priority, err := strconv.Atoi(fields[17])
	if err != nil {
		return 0, 0, fmt.Errorf("failed to parse priority: %v", err)
	}

	// Parse nice value
	nice, err := strconv.Atoi(fields[18])
	if err != nil {
		return 0, 0, fmt.Errorf("failed to parse nice value: %v", err)
	}

	return priority, nice, nil
}

func getProcessStartTime(pid int) (time.Time, error) {
	// Read /proc/<pid>/stat
	content, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to read process stats: %v", err)
	}

	fields := strings.Fields(string(content))
	if len(fields) < 22 {
		return time.Time{}, fmt.Errorf("invalid process stats format")
	}

	// Parse start time
	startTime, err := strconv.ParseInt(fields[21], 10, 64)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to parse start time: %v", err)
	}

	// Convert to time.Time
	return time.Unix(startTime, 0), nil
}

func getWorkingDir(pid int) (string, error) {
	// Read /proc/<pid>/cwd
	workingDir, err := os.Readlink(filepath.Join("/proc", strconv.Itoa(pid), "cwd"))
	if err != nil {
		return "", fmt.Errorf("failed to read working directory: %v", err)
	}

	return workingDir, nil
}

func getEnvironment(pid int) ([]string, error) {
	// Read /proc/<pid>/environ
	content, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "environ"))
	if err != nil {
		return nil, fmt.Errorf("failed to read environment: %v", err)
	}

	// Split by null bytes
	env := strings.Split(string(content), "\x00")
	return env, nil
}

func getCapabilities(pid int) ([]string, error) {
	// Read /proc/<pid>/status
	content, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "status"))
	if err != nil {
		return nil, fmt.Errorf("failed to read process status: %v", err)
	}

	var capabilities []string
	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		fields := strings.SplitN(line, ":", 2)
		if len(fields) != 2 {
			continue
		}

		if strings.TrimSpace(fields[0]) == "CapInh" || strings.TrimSpace(fields[0]) == "CapPrm" || strings.TrimSpace(fields[0]) == "CapEff" {
			cap := strings.TrimSpace(fields[1])
			if cap != "0000000000000000" {
				capabilities = append(capabilities, cap)
			}
		}
	}

	return capabilities, nil
}

func getResourceLimits(pid int) (ProcessLimits, error) {
	var limits ProcessLimits

	// Read /proc/<pid>/limits
	content, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "limits"))
	if err != nil {
		return limits, fmt.Errorf("failed to read resource limits: %v", err)
	}

	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		limit := fields[3]
		if limit == "unlimited" {
			limit = "-1"
		}

		value, err := strconv.ParseInt(limit, 10, 64)
		if err != nil {
			continue
		}

		// Use the first two fields to match resource type
		resource := strings.ToLower(fields[0] + " " + fields[1])
		switch resource {
		case "max open":
			limits.MaxFileDescriptors = value
		case "max processes":
			limits.MaxProcesses = value
		case "max stack":
			limits.MaxStackSize = value
		case "max core":
			limits.MaxCoreFileSize = value
		case "max resident":
			limits.MaxResidentSetSize = value
		case "max virtual":
			limits.MaxVirtualMemory = value
		case "max cpu":
			limits.MaxCPUTime = value
		case "max file":
			limits.MaxFileSize = value
		case "max data":
			limits.MaxDataSize = value
		case "max address":
			limits.MaxAddressSpace = value
		case "max locked":
			limits.MaxLockedMemory = value
		case "max real-time":
			// Could be priority or timeout, check next field if available
			if len(fields) > 2 {
				sub := strings.ToLower(fields[2])
				switch sub {
				case "priority":
					limits.MaxRealTimePriority = value
				case "timeout":
					limits.MaxRealTimeTimeout = value
				}
			}
		case "max message":
			limits.MaxMessageQueues = value
		case "max pending":
			limits.MaxPendingSignals = value
		case "max posix":
			limits.MaxPOSIXMessageQueues = value
		}
	}

	return limits, nil
}

// GetProcessByPID retrieves information about a specific process
func GetProcessByPID(ctx context.Context, pid int) (ProcessInfo, error) {
	return getProcessDetails(pid)
}

// GetProcessesByName retrieves information about processes with a specific name
func GetProcessesByName(ctx context.Context, name string) ([]ProcessInfo, error) {
	var processes []ProcessInfo

	// Get all processes
	allProcesses, err := GetProcessInfo(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get process information: %v", err)
	}

	// Filter processes by name
	for _, process := range allProcesses {
		if process.Name == name {
			processes = append(processes, process)
		}
	}

	return processes, nil
}
