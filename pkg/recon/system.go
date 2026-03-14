package recon

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"kubeshadow/pkg/logger"
)

// SystemInfo represents system-related information
type SystemInfo struct {
	Hostname      string
	OSInfo        OSInfo
	CPUInfo       CPUInfo
	MemoryInfo    MemoryInfo
	DiskInfo      []DiskInfo
	UserInfo      []UserInfo
	Environment   []string
	BootTime      time.Time
	Uptime        time.Duration
	LoadAverage   []float64
	KernelVersion string
	Architecture  string
	Timezone      string
	Locale        string
}

// OSInfo represents operating system information
type OSInfo struct {
	Name         string
	Version      string
	Distribution string
	Release      string
	CodeName     string
}

// CPUInfo represents CPU information
type CPUInfo struct {
	Model       string
	Cores       int
	Threads     int
	Frequency   float64
	Cache       int64
	Flags       []string
	Temperature float64
	Usage       float64
}

// MemoryInfo represents memory information
type MemoryInfo struct {
	Total     int64
	Used      int64
	Free      int64
	Shared    int64
	Buffers   int64
	Cached    int64
	SwapTotal int64
	SwapUsed  int64
	SwapFree  int64
}

// DiskInfo represents disk information
type DiskInfo struct {
	Device      string
	MountPoint  string
	FSType      string
	Total       int64
	Used        int64
	Free        int64
	InodesTotal int64
	InodesUsed  int64
	InodesFree  int64
	ReadOnly    bool
}

// UserInfo represents user information
type UserInfo struct {
	Username    string
	UID         int
	GID         int
	HomeDir     string
	Shell       string
	Groups      []string
	LastLogin   time.Time
	LoginShell  string
	RealName    string
	PhoneNumber string
	Office      string
}

// GetSystemInfo retrieves system-related information
func GetSystemInfo(ctx context.Context) (SystemInfo, error) {
	var info SystemInfo

	// Get hostname
	hostname, err := getHostname()
	if err != nil {
		return info, fmt.Errorf("failed to get hostname: %v", err)
	}
	info.Hostname = hostname

	// Get OS information
	osInfo, err := getOSInfo()
	if err != nil {
		return info, fmt.Errorf("failed to get OS information: %v", err)
	}
	info.OSInfo = osInfo

	// Get CPU information
	cpuInfo, err := getCPUInfo()
	if err != nil {
		return info, fmt.Errorf("failed to get CPU information: %v", err)
	}
	info.CPUInfo = cpuInfo

	// Get memory information
	memoryInfo, err := getMemoryInfo()
	if err != nil {
		return info, fmt.Errorf("failed to get memory information: %v", err)
	}
	info.MemoryInfo = memoryInfo

	// Get disk information
	diskInfo, err := getDiskInfo()
	if err != nil {
		return info, fmt.Errorf("failed to get disk information: %v", err)
	}
	info.DiskInfo = diskInfo

	// Get user information
	userInfo, err := getUserInfo()
	if err != nil {
		return info, fmt.Errorf("failed to get user information: %v", err)
	}
	info.UserInfo = userInfo

	// Get environment variables
	env, err := getSystemEnvironment()
	if err != nil {
		return info, fmt.Errorf("failed to get environment variables: %v", err)
	}
	info.Environment = env

	// Get boot time
	bootTime, err := getBootTime()
	if err != nil {
		return info, fmt.Errorf("failed to get boot time: %v", err)
	}
	info.BootTime = bootTime

	// Calculate uptime
	info.Uptime = time.Since(bootTime)

	// Get load average
	loadAvg, err := getLoadAverage()
	if err != nil {
		return info, fmt.Errorf("failed to get load average: %v", err)
	}
	info.LoadAverage = loadAvg

	// Get kernel version
	kernelVersion, err := getKernelVersion()
	if err != nil {
		return info, fmt.Errorf("failed to get kernel version: %v", err)
	}
	info.KernelVersion = kernelVersion

	// Get architecture
	arch, err := getArchitecture()
	if err != nil {
		return info, fmt.Errorf("failed to get architecture: %v", err)
	}
	info.Architecture = arch

	// Get timezone
	timezone, err := getTimezone()
	if err != nil {
		return info, fmt.Errorf("failed to get timezone: %v", err)
	}
	info.Timezone = timezone

	// Get locale
	locale, err := getLocale()
	if err != nil {
		return info, fmt.Errorf("failed to get locale: %v", err)
	}
	info.Locale = locale

	return info, nil
}

func getHostname() (string, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return "", fmt.Errorf("failed to get hostname: %v", err)
	}
	return hostname, nil
}

func getOSInfo() (OSInfo, error) {
	var info OSInfo

	// Try to detect OS using runtime.GOOS
	switch runtime.GOOS {
	case "darwin":
		info.Name = "macOS"
		// Try to get macOS version
		cmd := exec.Command("sw_vers", "-productVersion")
		if output, err := cmd.Output(); err == nil {
			info.Version = strings.TrimSpace(string(output))
		}
		info.Distribution = "darwin"
	case "linux":
		// Read /etc/os-release
		content, err := os.ReadFile("/etc/os-release")
		if err != nil {
			// Fallback to /etc/issue
			if issueContent, err := os.ReadFile("/etc/issue"); err == nil {
				info.Name = strings.TrimSpace(string(issueContent))
			} else {
				info.Name = "Linux"
			}
		} else {
			lines := strings.Split(string(content), "\n")
			for _, line := range lines {
				fields := strings.SplitN(line, "=", 2)
				if len(fields) != 2 {
					continue
				}

				key := strings.TrimSpace(fields[0])
				value := strings.Trim(strings.TrimSpace(fields[1]), "\"")

				switch key {
				case "NAME":
					info.Name = value
				case "VERSION":
					info.Version = value
				case "ID":
					info.Distribution = value
				case "VERSION_ID":
					info.Release = value
				case "VERSION_CODENAME":
					info.CodeName = value
				}
			}
		}
	case "windows":
		info.Name = "Windows"
		// Try to get Windows version
		cmd := exec.Command("cmd", "/c", "ver")
		if output, err := cmd.Output(); err == nil {
			info.Version = strings.TrimSpace(string(output))
		}
		info.Distribution = "windows"
	default:
		info.Name = runtime.GOOS
		info.Distribution = runtime.GOOS
	}

	return info, nil
}

func getCPUInfo() (CPUInfo, error) {
	var info CPUInfo

	// Set default values
	info.Cores = runtime.NumCPU()
	info.Threads = runtime.NumCPU()

	switch runtime.GOOS {
	case "linux":
		// Read /proc/cpuinfo
		content, err := os.ReadFile("/proc/cpuinfo")
		if err != nil {
			return info, fmt.Errorf("failed to read /proc/cpuinfo: %v", err)
		}

		lines := strings.Split(string(content), "\n")
		for _, line := range lines {
			fields := strings.SplitN(line, ":", 2)
			if len(fields) != 2 {
				continue
			}

			key := strings.TrimSpace(fields[0])
			value := strings.TrimSpace(fields[1])

			switch key {
			case "model name":
				info.Model = value
			case "cpu cores":
				cores, err := strconv.Atoi(value)
				if err != nil {
					continue
				}
				info.Cores = cores
			case "siblings":
				threads, err := strconv.Atoi(value)
				if err != nil {
					continue
				}
				info.Threads = threads
			case "cpu MHz":
				freq, err := strconv.ParseFloat(value, 64)
				if err != nil {
					continue
				}
				info.Frequency = freq
			case "cache size":
				cache := strings.Fields(value)[0]
				size, err := strconv.ParseInt(cache, 10, 64)
				if err != nil {
					continue
				}
				info.Cache = size
			case "flags":
				info.Flags = strings.Fields(value)
			}
		}
	case "darwin":
		// macOS - try to get CPU info using sysctl
		cmd := exec.Command("sysctl", "-n", "machdep.cpu.brand_string")
		if output, err := cmd.Output(); err == nil {
			info.Model = strings.TrimSpace(string(output))
		}
		
		cmd = exec.Command("sysctl", "-n", "hw.ncpu")
		if output, err := cmd.Output(); err == nil {
			if cores, err := strconv.Atoi(strings.TrimSpace(string(output))); err == nil {
				info.Cores = cores
			}
		}
		
		cmd = exec.Command("sysctl", "-n", "hw.cpufrequency")
		if output, err := cmd.Output(); err == nil {
			if freq, err := strconv.ParseFloat(strings.TrimSpace(string(output)), 64); err == nil {
				info.Frequency = freq / 1000000 // Convert to MHz
			}
		}
	case "windows":
		// Windows - basic info
		info.Model = "Windows CPU"
		info.Cores = runtime.NumCPU()
	default:
		info.Model = "Unknown CPU"
		info.Cores = runtime.NumCPU()
	}

	// Get CPU temperature
	temp, err := getCPUTemperature()
	if err != nil {
		logger.Warn("Failed to get CPU temperature: %v", err)
	} else {
		info.Temperature = temp
	}

	// Get CPU usage
	usage, err := getCPUUsage()
	if err != nil {
		logger.Warn("Failed to get CPU usage: %v", err)
	} else {
		info.Usage = usage
	}

	return info, nil
}

func getCPUTemperature() (float64, error) {
	switch runtime.GOOS {
	case "linux":
		// Read /sys/class/thermal/thermal_zone0/temp
		content, err := os.ReadFile("/sys/class/thermal/thermal_zone0/temp")
		if err != nil {
			return 0, fmt.Errorf("failed to read CPU temperature: %v", err)
		}

		temp, err := strconv.ParseFloat(strings.TrimSpace(string(content)), 64)
		if err != nil {
			return 0, fmt.Errorf("failed to parse CPU temperature: %v", err)
		}

		return temp / 1000.0, nil
	case "darwin":
		// macOS - CPU temperature not easily accessible without sudo
		// Return 0 to indicate not available rather than error
		return 0, nil
	default:
		return 0, fmt.Errorf("CPU temperature not supported on %s", runtime.GOOS)
	}
}

func getCPUUsage() (float64, error) {
	switch runtime.GOOS {
	case "linux":
		// Read /proc/stat
		content, err := os.ReadFile("/proc/stat")
		if err != nil {
			return 0, fmt.Errorf("failed to read /proc/stat: %v", err)
		}

		lines := strings.Split(string(content), "\n")
		for _, line := range lines {
			if !strings.HasPrefix(line, "cpu ") {
				continue
			}

			fields := strings.Fields(line)
			if len(fields) < 8 {
				return 0, fmt.Errorf("invalid CPU stats format")
			}

			// Parse CPU times
			user, err := strconv.ParseInt(fields[1], 10, 64)
			if err != nil {
				return 0, fmt.Errorf("failed to parse user time: %v", err)
			}

			nice, err := strconv.ParseInt(fields[2], 10, 64)
			if err != nil {
				return 0, fmt.Errorf("failed to parse nice time: %v", err)
			}

			system, err := strconv.ParseInt(fields[3], 10, 64)
			if err != nil {
				return 0, fmt.Errorf("failed to parse system time: %v", err)
			}

			idle, err := strconv.ParseInt(fields[4], 10, 64)
			if err != nil {
				return 0, fmt.Errorf("failed to parse idle time: %v", err)
			}

			// Calculate CPU usage
			total := user + nice + system + idle
			used := total - idle
			usage := float64(used) / float64(total) * 100.0

			return usage, nil
		}

		return 0, fmt.Errorf("CPU stats not found")
	case "darwin":
		// macOS - use top command
		cmd := exec.Command("top", "-l", "1", "-n", "0")
		output, err := cmd.Output()
		if err != nil {
			return 0, fmt.Errorf("failed to get CPU usage on macOS: %v", err)
		}

		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.Contains(line, "CPU usage:") {
				fields := strings.Fields(line)
				for i, field := range fields {
					if field == "CPU" && i+2 < len(fields) {
						usageStr := strings.TrimSuffix(fields[i+2], "%")
						usage, err := strconv.ParseFloat(usageStr, 64)
						if err == nil {
							return usage, nil
						}
					}
				}
			}
		}
		return 0, fmt.Errorf("CPU usage not found in top output")
	default:
		return 0, fmt.Errorf("CPU usage not supported on %s", runtime.GOOS)
	}
}

func getMemoryInfo() (MemoryInfo, error) {
	var info MemoryInfo

	switch runtime.GOOS {
	case "linux":
		// Read /proc/meminfo
		content, err := os.ReadFile("/proc/meminfo")
		if err != nil {
			return info, fmt.Errorf("failed to read /proc/meminfo: %v", err)
		}

		lines := strings.Split(string(content), "\n")
		for _, line := range lines {
			fields := strings.SplitN(line, ":", 2)
			if len(fields) != 2 {
				continue
			}

			key := strings.TrimSpace(fields[0])
			value := strings.Fields(strings.TrimSpace(fields[1]))[0]
			size, err := strconv.ParseInt(value, 10, 64)
			if err != nil {
				continue
			}

			switch key {
			case "MemTotal":
				info.Total = size * 1024
			case "MemFree":
				info.Free = size * 1024
			case "MemShared":
				info.Shared = size * 1024
			case "Buffers":
				info.Buffers = size * 1024
			case "Cached":
				info.Cached = size * 1024
			case "SwapTotal":
				info.SwapTotal = size * 1024
			case "SwapFree":
				info.SwapFree = size * 1024
			}
		}

		// Calculate used memory
		info.Used = info.Total - info.Free - info.Buffers - info.Cached
		info.SwapUsed = info.SwapTotal - info.SwapFree

	case "darwin":
		// macOS - use vm_stat command
		cmd := exec.Command("vm_stat")
		output, err := cmd.Output()
		if err != nil {
			return info, fmt.Errorf("failed to get memory info on macOS: %v", err)
		}

		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}

			key := strings.TrimSuffix(fields[0], ":")
			value := strings.TrimSuffix(fields[1], ".")

			size, err := strconv.ParseInt(value, 10, 64)
			if err != nil {
				continue
			}

			// Convert pages to bytes (4096 bytes per page on macOS)
			sizeBytes := size * 4096

			switch key {
			case "Pages free":
				info.Free = sizeBytes
			case "Pages active":
				info.Used += sizeBytes
			case "Pages inactive":
				info.Used += sizeBytes
			case "Pages wired down":
				info.Used += sizeBytes
			case "Pages speculative":
				info.Used += sizeBytes
			}
		}

		// Get total memory using sysctl
		cmd = exec.Command("sysctl", "-n", "hw.memsize")
		if output, err := cmd.Output(); err == nil {
			if total, err := strconv.ParseInt(strings.TrimSpace(string(output)), 10, 64); err == nil {
				info.Total = total
			}
		}

	case "windows":
		// Windows - basic info
		info.Total = 0 // Would need Windows API calls for detailed info
		info.Free = 0
		info.Used = 0

	default:
		// Fallback for other operating systems
		info.Total = 0
		info.Free = 0
		info.Used = 0
	}

	return info, nil
}

func getDiskInfo() ([]DiskInfo, error) {
	var disks []DiskInfo

	switch runtime.GOOS {
	case "linux":
		// Read /proc/mounts
		content, err := os.ReadFile("/proc/mounts")
		if err != nil {
			return nil, fmt.Errorf("failed to read /proc/mounts: %v", err)
		}

	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		device := fields[0]
		mountPoint := fields[1]
		fsType := fields[2]
		options := fields[3]

		// Skip non-physical devices
		if strings.HasPrefix(device, "/dev/") {
			var disk DiskInfo
			disk.Device = device
			disk.MountPoint = mountPoint
			disk.FSType = fsType
			disk.ReadOnly = strings.Contains(options, "ro")

			// Get disk statistics
			cmd := exec.Command("df", "-B1", mountPoint)
			output, err := cmd.Output()
			if err != nil {
				logger.Warn("Failed to get disk statistics for %s: %v", mountPoint, err)
				continue
			}

			lines := strings.Split(string(output), "\n")
			if len(lines) < 2 {
				continue
			}

			fields := strings.Fields(lines[1])
			if len(fields) < 4 {
				continue
			}

			total, err := strconv.ParseInt(fields[1], 10, 64)
			if err != nil {
				continue
			}
			disk.Total = total

			used, err := strconv.ParseInt(fields[2], 10, 64)
			if err != nil {
				continue
			}
			disk.Used = used

			free, err := strconv.ParseInt(fields[3], 10, 64)
			if err != nil {
				continue
			}
			disk.Free = free

			// Get inode statistics
			cmd = exec.Command("df", "-i", mountPoint)
			output, err = cmd.Output()
			if err != nil {
				logger.Warn("Failed to get inode statistics for %s: %v", mountPoint, err)
				continue
			}

			lines = strings.Split(string(output), "\n")
			if len(lines) < 2 {
				continue
			}

			fields = strings.Fields(lines[1])
			if len(fields) < 4 {
				continue
			}

			inodesTotal, err := strconv.ParseInt(fields[1], 10, 64)
			if err != nil {
				continue
			}
			disk.InodesTotal = inodesTotal

			inodesUsed, err := strconv.ParseInt(fields[2], 10, 64)
			if err != nil {
				continue
			}
			disk.InodesUsed = inodesUsed

			inodesFree, err := strconv.ParseInt(fields[3], 10, 64)
			if err != nil {
				continue
			}
			disk.InodesFree = inodesFree

			disks = append(disks, disk)
		}
	}

	case "darwin":
		// macOS - use df command without -B1 flag which might not be supported
		cmd := exec.Command("df")
		output, err := cmd.Output()
		if err != nil {
			return nil, fmt.Errorf("failed to get disk info on macOS: %v", err)
		}

		lines := strings.Split(string(output), "\n")
		for i, line := range lines {
			if i == 0 || line == "" {
				continue
			}

			fields := strings.Fields(line)
			if len(fields) < 6 {
				continue
			}

			var disk DiskInfo
			disk.Device = fields[0]
			disk.MountPoint = fields[8] // Mount point is typically the last field
			disk.FSType = fields[8] // Filesystem type is typically field 8

			// Parse size in 512-byte blocks and convert to bytes
			total, err := strconv.ParseInt(fields[1], 10, 64)
			if err != nil {
				continue
			}
			disk.Total = total * 512

			used, err := strconv.ParseInt(fields[2], 10, 64)
			if err != nil {
				continue
			}
			disk.Used = used * 512

			free, err := strconv.ParseInt(fields[3], 10, 64)
			if err != nil {
				continue
			}
			disk.Free = free * 512

			disks = append(disks, disk)
		}

	case "windows":
		// Windows - basic info
		// Would need Windows API calls for detailed disk info
		var disk DiskInfo
		disk.Device = "C:"
		disk.MountPoint = "C:\\"
		disk.FSType = "NTFS"
		disks = append(disks, disk)

	default:
		// Fallback for other operating systems
		var disk DiskInfo
		disk.Device = "unknown"
		disk.MountPoint = "/"
		disk.FSType = "unknown"
		disks = append(disks, disk)
	}

	return disks, nil
}

func getUserInfo() ([]UserInfo, error) {
	var users []UserInfo

	// Read /etc/passwd
	content, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return nil, fmt.Errorf("failed to read /etc/passwd: %v", err)
	}

	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		fields := strings.Split(line, ":")
		if len(fields) < 7 {
			continue
		}

		var user UserInfo
		user.Username = fields[0]

		uid, err := strconv.Atoi(fields[2])
		if err != nil {
			continue
		}
		user.UID = uid

		gid, err := strconv.Atoi(fields[3])
		if err != nil {
			continue
		}
		user.GID = gid

		user.RealName = fields[4]
		user.HomeDir = fields[5]
		user.Shell = fields[6]

		// Get user groups
		cmd := exec.Command("groups", user.Username)
		output, err := cmd.Output()
		if err != nil {
			logger.Warn("Failed to get groups for user %s: %v", user.Username, err)
		} else {
			groups := strings.Fields(string(output))
			if len(groups) > 2 {
				user.Groups = groups[2:]
			}
		}

		// Get last login
		cmd = exec.Command("last", "-n", "1", user.Username)
		output, err = cmd.Output()
		if err != nil {
			logger.Warn("Failed to get last login for user %s: %v", user.Username, err)
		} else {
			lines := strings.Split(string(output), "\n")
			if len(lines) > 1 {
				fields := strings.Fields(lines[0])
				if len(fields) > 3 {
					lastLogin, err := time.Parse("Mon Jan 2 15:04:05 2006", strings.Join(fields[3:], " "))
					if err == nil {
						user.LastLogin = lastLogin
					}
				}
			}
		}

		users = append(users, user)
	}

	return users, nil
}

func getSystemEnvironment() ([]string, error) {
	return os.Environ(), nil
}

func getBootTime() (time.Time, error) {
	switch runtime.GOOS {
	case "linux":
		// Read /proc/uptime
		content, err := os.ReadFile("/proc/uptime")
		if err != nil {
			return time.Time{}, fmt.Errorf("failed to read /proc/uptime: %v", err)
		}

		fields := strings.Fields(string(content))
		if len(fields) < 1 {
			return time.Time{}, fmt.Errorf("invalid uptime format")
		}

		uptime, err := strconv.ParseFloat(fields[0], 64)
		if err != nil {
			return time.Time{}, fmt.Errorf("failed to parse uptime: %v", err)
		}

		return time.Now().Add(-time.Duration(uptime) * time.Second), nil
	case "darwin":
		// macOS - use sysctl to get boot time
		cmd := exec.Command("sysctl", "-n", "kern.boottime")
		output, err := cmd.Output()
		if err != nil {
			return time.Time{}, fmt.Errorf("failed to get boot time on macOS: %v", err)
		}

		// Parse output like: { sec = 1234567890, usec = 123456 }
		outputStr := strings.TrimSpace(string(output))
		if strings.HasPrefix(outputStr, "{ sec = ") {
			secStr := strings.Split(strings.Split(outputStr, "sec = ")[1], ",")[0]
			sec, err := strconv.ParseInt(secStr, 10, 64)
			if err == nil {
				return time.Unix(sec, 0), nil
			}
		}
		return time.Time{}, fmt.Errorf("failed to parse boot time on macOS")
	default:
		return time.Time{}, fmt.Errorf("boot time not supported on %s", runtime.GOOS)
	}
}

func getLoadAverage() ([]float64, error) {
	switch runtime.GOOS {
	case "linux":
		// Read /proc/loadavg
		content, err := os.ReadFile("/proc/loadavg")
		if err != nil {
			return nil, fmt.Errorf("failed to read /proc/loadavg: %v", err)
		}

		fields := strings.Fields(string(content))
		if len(fields) < 3 {
			return nil, fmt.Errorf("invalid load average format")
		}

		var loadAvg []float64
		for i := 0; i < 3; i++ {
			load, err := strconv.ParseFloat(fields[i], 64)
			if err != nil {
				return nil, fmt.Errorf("failed to parse load average: %v", err)
			}
			loadAvg = append(loadAvg, load)
		}

		return loadAvg, nil
	case "darwin":
		// macOS - use sysctl to get load average
		cmd := exec.Command("sysctl", "-n", "vm.loadavg")
		output, err := cmd.Output()
		if err != nil {
			return nil, fmt.Errorf("failed to get load average on macOS: %v", err)
		}

		// Parse output like: { 1.23 1.45 1.67 }
		outputStr := strings.TrimSpace(string(output))
		outputStr = strings.Trim(outputStr, "{}")
		fields := strings.Fields(outputStr)

		var loadAvg []float64
		for _, field := range fields {
			load, err := strconv.ParseFloat(field, 64)
			if err != nil {
				continue
			}
			loadAvg = append(loadAvg, load)
		}

		return loadAvg, nil
	default:
		return nil, fmt.Errorf("load average not supported on %s", runtime.GOOS)
	}
}

func getKernelVersion() (string, error) {
	switch runtime.GOOS {
	case "linux":
		// Read /proc/version
		content, err := os.ReadFile("/proc/version")
		if err != nil {
			return "", fmt.Errorf("failed to read /proc/version: %v", err)
		}

		return strings.TrimSpace(string(content)), nil
	case "darwin":
		// macOS - use uname to get kernel version
		cmd := exec.Command("uname", "-r")
		output, err := cmd.Output()
		if err != nil {
			return "", fmt.Errorf("failed to get kernel version on macOS: %v", err)
		}

		return strings.TrimSpace(string(output)), nil
	default:
		return "", fmt.Errorf("kernel version not supported on %s", runtime.GOOS)
	}
}

func getArchitecture() (string, error) {
	cmd := exec.Command("uname", "-m")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to get architecture: %v", err)
	}

	return strings.TrimSpace(string(output)), nil
}

func getTimezone() (string, error) {
	switch runtime.GOOS {
	case "linux":
		// Read /etc/timezone
		content, err := os.ReadFile("/etc/timezone")
		if err != nil {
			return "", fmt.Errorf("failed to read /etc/timezone: %v", err)
		}

		return strings.TrimSpace(string(content)), nil
	case "darwin":
		// macOS - return UTC as fallback
		return "UTC", nil
	default:
		return "", fmt.Errorf("timezone not supported on %s", runtime.GOOS)
	}
}

func getLocale() (string, error) {
	switch runtime.GOOS {
	case "linux":
		// Read /etc/default/locale
		content, err := os.ReadFile("/etc/default/locale")
		if err != nil {
			return "", fmt.Errorf("failed to read /etc/default/locale: %v", err)
		}

		lines := strings.Split(string(content), "\n")
		for _, line := range lines {
			fields := strings.SplitN(line, "=", 2)
			if len(fields) != 2 {
				continue
			}

			if strings.TrimSpace(fields[0]) == "LANG" {
				return strings.Trim(strings.TrimSpace(fields[1]), "\""), nil
			}
		}

		return "", fmt.Errorf("locale not found")
	case "darwin":
		// macOS - return en_US as fallback
		return "en_US", nil
	default:
		return "", fmt.Errorf("locale not supported on %s", runtime.GOOS)
	}
}
