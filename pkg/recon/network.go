package recon

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"kubeshadow/pkg/logger"
)

// NetworkInfo represents network-related information
type NetworkInfo struct {
	Hostname      string
	IPAddresses   []IPAddress
	DNSServers    []string
	OpenPorts     []Port
	Interfaces    []Interface
	Routes        []Route
	Connections   []Connection
	FirewallRules []FirewallRule
}

// IPAddress represents an IP address with its properties
type IPAddress struct {
	Address     string
	Netmask     string
	Broadcast   string
	Interface   string
	IsIPv6      bool
	IsLoopback  bool
	IsPrivate   bool
	IsPublic    bool
	IsMulticast bool
}

// Port represents a network port with its properties
type Port struct {
	Number      int
	Protocol    string
	State       string
	Service     string
	Process     string
	User        string
	LocalAddr   string
	RemoteAddr  string
	IsListening bool
	IsTCP       bool
	IsUDP       bool
}

// Interface represents a network interface with its properties
type Interface struct {
	Name           string
	Index          int
	MTU            int
	HardwareAddr   string
	Flags          []string
	Addresses      []IPAddress
	Stats          InterfaceStats
	IsUp           bool
	IsLoopback     bool
	IsPointToPoint bool
	IsMulticast    bool
	IsBroadcast    bool
}

// InterfaceStats represents network interface statistics
type InterfaceStats struct {
	BytesReceived   int64
	BytesSent       int64
	PacketsReceived int64
	PacketsSent     int64
	ErrorsReceived  int64
	ErrorsSent      int64
	DropsReceived   int64
	DropsSent       int64
	FIFOErrors      int64
	FrameErrors     int64
	Collisions      int64
	CarrierErrors   int64
	Compressed      int64
	Multicast       int64
}

// Route represents a network route with its properties
type Route struct {
	Destination string
	Gateway     string
	Netmask     string
	Interface   string
	Metric      int
	IsDefault   bool
	IsHost      bool
	IsNetwork   bool
	IsGateway   bool
}

// Connection represents a network connection with its properties
type Connection struct {
	LocalAddr     string
	LocalPort     int
	RemoteAddr    string
	RemotePort    int
	State         string
	Protocol      string
	Process       string
	User          string
	Inode         int64
	IsTCP         bool
	IsUDP         bool
	IsListening   bool
	IsEstablished bool
}

// FirewallRule represents a firewall rule with its properties
type FirewallRule struct {
	Chain       string
	Target      string
	Protocol    string
	Source      string
	Destination string
	Sport       string
	Dport       string
	Interface   string
	Options     []string
	Comment     string
}

// GetNetworkInfo retrieves network-related information
func GetNetworkInfo(ctx context.Context) (*NetworkInfo, error) {
	info := &NetworkInfo{}

	// Get hostname
	hostname, err := os.Hostname()
	if err != nil {
		return nil, fmt.Errorf("failed to get hostname: %v", err)
	}
	info.Hostname = hostname

	// Get IP addresses
	ipAddresses, err := getIPAddresses()
	if err != nil {
		return nil, fmt.Errorf("failed to get IP addresses: %v", err)
	}
	info.IPAddresses = ipAddresses

	// Get DNS servers
	dnsServers, err := getDNSServers()
	if err != nil {
		return nil, fmt.Errorf("failed to get DNS servers: %v", err)
	}
	info.DNSServers = dnsServers

	// Get open ports
	openPorts, err := getOpenPorts()
	if err != nil {
		return nil, fmt.Errorf("failed to get open ports: %v", err)
	}
	info.OpenPorts = openPorts

	// Get network interfaces
	interfaces, err := getNetworkInterfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to get network interfaces: %v", err)
	}
	info.Interfaces = interfaces

	// Get routes
	routes, err := getRoutes()
	if err != nil {
		return nil, fmt.Errorf("failed to get routes: %v", err)
	}
	info.Routes = routes

	// Get connections
	connections, err := getConnections()
	if err != nil {
		return nil, fmt.Errorf("failed to get connections: %v", err)
	}
	info.Connections = connections

	// Get firewall rules
	firewallRules, err := getFirewallRules()
	if err != nil {
		return nil, fmt.Errorf("failed to get firewall rules: %v", err)
	}
	info.FirewallRules = firewallRules

	return info, nil
}

func getIPAddresses() ([]IPAddress, error) {
	var addresses []IPAddress

	// Get all network interfaces
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to get network interfaces: %v", err)
	}

	for _, iface := range interfaces {
		// Get interface addresses
		addrs, err := iface.Addrs()
		if err != nil {
			logger.Warn("Failed to get addresses for interface %s: %v", iface.Name, err)
			continue
		}

		for _, addr := range addrs {
			// Parse IP address
			ip, ipnet, err := net.ParseCIDR(addr.String())
			if err != nil {
				logger.Warn("Failed to parse IP address %s: %v", addr.String(), err)
				continue
			}

			// Calculate broadcast address
			broadcast := ""
			if ip.To4() != nil {
				// For IPv4
				mask := ipnet.Mask
				ipv4 := ip.To4()
				broadcast = net.IPv4(
					ipv4[0]|^mask[0],
					ipv4[1]|^mask[1],
					ipv4[2]|^mask[2],
					ipv4[3]|^mask[3],
				).String()
			}

			// Check IP properties
			isIPv6 := ip.To4() == nil
			isLoopback := ip.IsLoopback()
			isPrivate := ip.IsPrivate()
			isPublic := !isPrivate && !isLoopback
			isMulticast := ip.IsMulticast()

			addresses = append(addresses, IPAddress{
				Address:     ip.String(),
				Netmask:     net.IP(ipnet.Mask).String(),
				Broadcast:   broadcast,
				Interface:   iface.Name,
				IsIPv6:      isIPv6,
				IsLoopback:  isLoopback,
				IsPrivate:   isPrivate,
				IsPublic:    isPublic,
				IsMulticast: isMulticast,
			})
		}
	}

	return addresses, nil
}

func getDNSServers() ([]string, error) {
	var servers []string

	// Read /etc/resolv.conf
	content, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return nil, fmt.Errorf("failed to read /etc/resolv.conf: %v", err)
	}

	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		if fields[0] == "nameserver" {
			servers = append(servers, fields[1])
		}
	}

	return servers, nil
}

func getOpenPorts() ([]Port, error) {
	var ports []Port

	// Check if we're on a platform that supports /proc filesystem
	if runtime.GOOS != "linux" {
		// Fallback to using netstat or ss command
		return getOpenPortsFallback()
	}

	// Get TCP ports
	tcpPorts, err := getTCPPorts()
	if err != nil {
		return nil, fmt.Errorf("failed to get TCP ports: %v", err)
	}
	ports = append(ports, tcpPorts...)

	// Get UDP ports
	udpPorts, err := getUDPPorts()
	if err != nil {
		return nil, fmt.Errorf("failed to get UDP ports: %v", err)
	}
	ports = append(ports, udpPorts...)

	return ports, nil
}

func getOpenPortsFallback() ([]Port, error) {
	var ports []Port

	// Try netstat first
	if netstatPorts, err := getNetstatPorts(); err == nil {
		ports = append(ports, netstatPorts...)
		return ports, nil
	}

	// Try ss command as fallback
	if ssPorts, err := getSSPorts(); err == nil {
		ports = append(ports, ssPorts...)
		return ports, nil
	}

	// If both fail, return empty list with info message
	logger.Info("Unable to get open ports on this platform")
	return ports, nil
}

func getNetstatPorts() ([]Port, error) {
	var ports []Port

	// Run netstat command with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "netstat", "-an")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to run netstat: %v", err)
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		// Parse protocol and address
		proto := fields[0]
		localAddr := fields[3]
		state := ""
		if len(fields) > 5 {
			state = fields[5]
		}

		// Parse port from address
		parts := strings.Split(localAddr, ":")
		if len(parts) < 2 {
			continue
		}

		portStr := parts[len(parts)-1]
		port, err := strconv.Atoi(portStr)
		if err != nil {
			continue
		}

		isTCP := strings.Contains(strings.ToLower(proto), "tcp")
		isUDP := strings.Contains(strings.ToLower(proto), "udp")
		isListening := strings.Contains(strings.ToLower(state), "listen")

		ports = append(ports, Port{
			Number:      port,
			Protocol:    strings.ToLower(proto),
			State:       state,
			Service:     getServiceName(port, strings.ToLower(proto)),
			Process:     "",
			User:        "",
			LocalAddr:   localAddr,
			RemoteAddr:  "",
			IsListening: isListening,
			IsTCP:       isTCP,
			IsUDP:       isUDP,
		})
	}

	return ports, nil
}

func getSSPorts() ([]Port, error) {
	var ports []Port

	// Run ss command with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "ss", "-tuln")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to run ss: %v", err)
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		// Parse protocol and address
		proto := fields[0]
		localAddr := fields[3]
		state := ""
		if len(fields) > 4 {
			state = fields[4]
		}

		// Parse port from address
		parts := strings.Split(localAddr, ":")
		if len(parts) < 2 {
			continue
		}

		portStr := parts[len(parts)-1]
		port, err := strconv.Atoi(portStr)
		if err != nil {
			continue
		}

		isTCP := strings.Contains(strings.ToLower(proto), "tcp")
		isUDP := strings.Contains(strings.ToLower(proto), "udp")
		isListening := strings.Contains(strings.ToLower(state), "listen")

		ports = append(ports, Port{
			Number:      port,
			Protocol:    strings.ToLower(proto),
			State:       state,
			Service:     getServiceName(port, strings.ToLower(proto)),
			Process:     "",
			User:        "",
			LocalAddr:   localAddr,
			RemoteAddr:  "",
			IsListening: isListening,
			IsTCP:       isTCP,
			IsUDP:       isUDP,
		})
	}

	return ports, nil
}

func getTCPPorts() ([]Port, error) {
	var ports []Port

	// Read /proc/net/tcp
	content, err := os.ReadFile("/proc/net/tcp")
	if err != nil {
		return nil, fmt.Errorf("failed to read /proc/net/tcp: %v", err)
	}

	lines := strings.Split(string(content), "\n")
	for i, line := range lines {
		if i == 0 {
			continue // Skip header
		}

		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		// Parse local address and port
		localAddr := fields[1]
		localPort, err := strconv.ParseInt(strings.Split(localAddr, ":")[1], 16, 32)
		if err != nil {
			continue
		}

		// Get process information
		process := ""
		user := ""
		if len(fields) > 9 {
			inode := fields[9]
			process, user = getProcessInfo(inode)
		}

		// Parse remote address and port
		remoteAddr := fields[2]
		// Parse state
		state, err := strconv.ParseInt(fields[3], 16, 32)
		if err != nil {
			continue
		}

		ports = append(ports, Port{
			Number:      int(localPort),
			Protocol:    "tcp",
			State:       getTCPState(int(state)),
			Service:     getServiceName(int(localPort), "tcp"),
			Process:     process,
			User:        user,
			LocalAddr:   localAddr,
			RemoteAddr:  remoteAddr,
			IsListening: int(state) == 10, // TCP_LISTEN
			IsTCP:       true,
			IsUDP:       false,
		})
	}

	return ports, nil
}

func getUDPPorts() ([]Port, error) {
	var ports []Port

	// Read /proc/net/udp
	content, err := os.ReadFile("/proc/net/udp")
	if err != nil {
		return nil, fmt.Errorf("failed to read /proc/net/udp: %v", err)
	}

	lines := strings.Split(string(content), "\n")
	for i, line := range lines {
		if i == 0 {
			continue // Skip header
		}

		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		// Parse local address and port
		localAddr := fields[1]
		localPort, err := strconv.ParseInt(strings.Split(localAddr, ":")[1], 16, 32)
		if err != nil {
			continue
		}

		// Get process information
		process := ""
		user := ""
		if len(fields) > 9 {
			inode := fields[9]
			process, user = getProcessInfo(inode)
		}

		// Parse remote address and port
		remoteAddr := fields[2]

		ports = append(ports, Port{
			Number:      int(localPort),
			Protocol:    "udp",
			State:       "NONE",
			Service:     getServiceName(int(localPort), "udp"),
			Process:     process,
			User:        user,
			LocalAddr:   localAddr,
			RemoteAddr:  remoteAddr,
			IsListening: true,
			IsTCP:       false,
			IsUDP:       true,
		})
	}

	return ports, nil
}

func getNetworkInterfaces() ([]Interface, error) {
	var interfaces []Interface

	// Get all network interfaces
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to get network interfaces: %v", err)
	}

	for _, iface := range ifaces {
		// Get interface addresses
		addrs, err := iface.Addrs()
		if err != nil {
			logger.Warn("Failed to get addresses for interface %s: %v", iface.Name, err)
			continue
		}

		var ipAddresses []IPAddress
		for _, addr := range addrs {
			ip, ipnet, err := net.ParseCIDR(addr.String())
			if err != nil {
				logger.Warn("Failed to parse IP address %s: %v", addr.String(), err)
				continue
			}

			// Calculate broadcast address
			broadcast := ""
			if ip.To4() != nil {
				// For IPv4
				mask := ipnet.Mask
				ipv4 := ip.To4()
				broadcast = net.IPv4(
					ipv4[0]|^mask[0],
					ipv4[1]|^mask[1],
					ipv4[2]|^mask[2],
					ipv4[3]|^mask[3],
				).String()
			}

			ipAddresses = append(ipAddresses, IPAddress{
				Address:     ip.String(),
				Netmask:     net.IP(ipnet.Mask).String(),
				Broadcast:   broadcast,
				Interface:   iface.Name,
				IsIPv6:      ip.To4() == nil,
				IsLoopback:  ip.IsLoopback(),
				IsPrivate:   ip.IsPrivate(),
				IsPublic:    !ip.IsPrivate() && !ip.IsLoopback(),
				IsMulticast: ip.IsMulticast(),
			})
		}

		// Get interface statistics
		stats, err := getInterfaceStats(iface.Name)
		if err != nil {
			logger.Warn("Failed to get statistics for interface %s: %v", iface.Name, err)
		}

		interfaces = append(interfaces, Interface{
			Name:           iface.Name,
			Index:          iface.Index,
			MTU:            iface.MTU,
			HardwareAddr:   iface.HardwareAddr.String(),
			Flags:          getInterfaceFlags(iface.Flags),
			Addresses:      ipAddresses,
			Stats:          stats,
			IsUp:           iface.Flags&net.FlagUp != 0,
			IsLoopback:     iface.Flags&net.FlagLoopback != 0,
			IsPointToPoint: iface.Flags&net.FlagPointToPoint != 0,
			IsMulticast:    iface.Flags&net.FlagMulticast != 0,
			IsBroadcast:    iface.Flags&net.FlagBroadcast != 0,
		})
	}

	return interfaces, nil
}

func getRoutes() ([]Route, error) {
	var routes []Route

	// Check if we're on a platform that supports /proc filesystem
	if runtime.GOOS != "linux" {
		// Fallback to using route command
		return getRoutesFallback()
	}

	// Read /proc/net/route
	content, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return nil, fmt.Errorf("failed to read /proc/net/route: %v", err)
	}

	lines := strings.Split(string(content), "\n")
	for i, line := range lines {
		if i == 0 {
			continue // Skip header
		}

		fields := strings.Fields(line)
		if len(fields) < 8 {
			continue
		}

		// Parse destination
		dest, err := strconv.ParseInt(fields[1], 16, 32)
		if err != nil {
			continue
		}

		// Parse gateway
		gw, err := strconv.ParseInt(fields[2], 16, 32)
		if err != nil {
			continue
		}

		// Parse netmask
		mask, err := strconv.ParseInt(fields[7], 16, 32)
		if err != nil {
			continue
		}

		// Convert IP addresses
		destIP := net.IPv4(byte(dest), byte(dest>>8), byte(dest>>16), byte(dest>>24))
		gwIP := net.IPv4(byte(gw), byte(gw>>8), byte(gw>>16), byte(gw>>24))
		maskIP := net.IPv4(byte(mask), byte(mask>>8), byte(mask>>16), byte(mask>>24))

		// Check route properties
		isDefault := dest == 0 && mask == 0
		isHost := mask == 0xffffffff
		isNetwork := !isDefault && !isHost
		isGateway := gw != 0

		routes = append(routes, Route{
			Destination: destIP.String(),
			Gateway:     gwIP.String(),
			Netmask:     maskIP.String(),
			Interface:   fields[0],
			Metric:      int(mask),
			IsDefault:   isDefault,
			IsHost:      isHost,
			IsNetwork:   isNetwork,
			IsGateway:   isGateway,
		})
	}

	return routes, nil
}

func getRoutesFallback() ([]Route, error) {
	var routes []Route

	// Try route command with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "route", "-n")
	output, err := cmd.Output()
	if err != nil {
		// Try netstat -r as fallback with timeout
		ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel2()

		cmd = exec.CommandContext(ctx2, "netstat", "-r")
		output, err = cmd.Output()
		if err != nil {
			logger.Info("Unable to get routes on this platform")
			return routes, nil
		}
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		// Skip header lines
		if fields[0] == "Destination" || fields[0] == "Kernel" {
			continue
		}

		destination := fields[0]
		gateway := fields[1]
		netmask := ""
		if len(fields) > 2 {
			netmask = fields[2]
		}
		interfaceName := ""
		if len(fields) > 3 {
			interfaceName = fields[3]
		}

		isDefault := destination == "default" || destination == "0.0.0.0"
		isHost := netmask == "255.255.255.255"
		isNetwork := !isDefault && !isHost
		isGateway := gateway != "*" && gateway != "0.0.0.0"

		routes = append(routes, Route{
			Destination: destination,
			Gateway:     gateway,
			Netmask:     netmask,
			Interface:   interfaceName,
			Metric:      0,
			IsDefault:   isDefault,
			IsHost:      isHost,
			IsNetwork:   isNetwork,
			IsGateway:   isGateway,
		})
	}

	return routes, nil
}

func getConnections() ([]Connection, error) {
	var connections []Connection

	// Check if we're on a platform that supports /proc filesystem
	if runtime.GOOS != "linux" {
		// Fallback to using netstat command
		return getConnectionsFallback()
	}

	// Get TCP connections
	tcpConns, err := getTCPConnections()
	if err != nil {
		return nil, fmt.Errorf("failed to get TCP connections: %v", err)
	}
	connections = append(connections, tcpConns...)

	// Get UDP connections
	udpConns, err := getUDPConnections()
	if err != nil {
		return nil, fmt.Errorf("failed to get UDP connections: %v", err)
	}
	connections = append(connections, udpConns...)

	return connections, nil
}

func getConnectionsFallback() ([]Connection, error) {
	var connections []Connection

	// Try netstat command with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "netstat", "-an")
	output, err := cmd.Output()
	if err != nil {
		logger.Info("Unable to get connections on this platform")
		return connections, nil
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		proto := fields[0]
		localAddr := fields[3]
		remoteAddr := ""
		state := ""
		if len(fields) > 4 {
			remoteAddr = fields[4]
		}
		if len(fields) > 5 {
			state = fields[5]
		}

		// Parse addresses
		localParts := strings.Split(localAddr, ":")
		remoteParts := strings.Split(remoteAddr, ":")

		if len(localParts) < 2 {
			continue
		}

		localPort, _ := strconv.Atoi(localParts[len(localParts)-1])
		remotePort := 0
		if len(remoteParts) >= 2 {
			remotePort, _ = strconv.Atoi(remoteParts[len(remoteParts)-1])
		}

		isTCP := strings.Contains(strings.ToLower(proto), "tcp")
		isUDP := strings.Contains(strings.ToLower(proto), "udp")

		connections = append(connections, Connection{
			LocalAddr:     localAddr,
			LocalPort:     localPort,
			RemoteAddr:    remoteAddr,
			RemotePort:    remotePort,
			State:         state,
			Protocol:      strings.ToLower(proto),
			Process:       "", // Process info not available in netstat output
			User:          "", // User info not available in netstat output
			Inode:         0,  // Inode info not available in netstat output
			IsTCP:         isTCP,
			IsUDP:         isUDP,
			IsListening:   false, // netstat doesn't show listening state directly
			IsEstablished: false, // netstat doesn't show established state directly
		})
	}

	return connections, nil
}

func getTCPConnections() ([]Connection, error) {
	var connections []Connection

	// Read /proc/net/tcp
	content, err := os.ReadFile("/proc/net/tcp")
	if err != nil {
		return nil, fmt.Errorf("failed to read /proc/net/tcp: %v", err)
	}

	lines := strings.Split(string(content), "\n")
	for i, line := range lines {
		if i == 0 {
			continue // Skip header
		}

		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		// Parse local address and port
		localAddr := fields[1]
		localPort, err := strconv.ParseInt(strings.Split(localAddr, ":")[1], 16, 32)
		if err != nil {
			continue
		}

		// Parse remote address and port
		remoteAddr := fields[2]
		remotePort, err := strconv.ParseInt(strings.Split(remoteAddr, ":")[1], 16, 32)
		if err != nil {
			continue
		}

		// Parse state
		state, err := strconv.ParseInt(fields[3], 16, 32)
		if err != nil {
			continue
		}

		// Get process information
		process := ""
		user := ""
		var inode int64
		if len(fields) > 9 {
			inode, err = strconv.ParseInt(fields[9], 10, 64)
			if err != nil {
				continue
			}
			process, user = getProcessInfo(fields[9])
		}

		connections = append(connections, Connection{
			LocalAddr:     localAddr,
			LocalPort:     int(localPort),
			RemoteAddr:    remoteAddr,
			RemotePort:    int(remotePort),
			State:         getTCPState(int(state)),
			Protocol:      "tcp",
			Process:       process,
			User:          user,
			Inode:         inode,
			IsTCP:         true,
			IsUDP:         false,
			IsListening:   int(state) == 10, // TCP_LISTEN
			IsEstablished: int(state) == 1,  // TCP_ESTABLISHED
		})
	}

	return connections, nil
}

func getUDPConnections() ([]Connection, error) {
	var connections []Connection

	// Read /proc/net/udp
	content, err := os.ReadFile("/proc/net/udp")
	if err != nil {
		return nil, fmt.Errorf("failed to read /proc/net/udp: %v", err)
	}

	lines := strings.Split(string(content), "\n")
	for i, line := range lines {
		if i == 0 {
			continue // Skip header
		}

		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		// Parse local address and port
		localAddr := fields[1]
		localPort, err := strconv.ParseInt(strings.Split(localAddr, ":")[1], 16, 32)
		if err != nil {
			continue
		}

		// Parse remote address and port
		remoteAddr := fields[2]
		remotePort, err := strconv.ParseInt(strings.Split(remoteAddr, ":")[1], 16, 32)
		if err != nil {
			continue
		}

		// Get process information
		process := ""
		user := ""
		var inode int64
		if len(fields) > 9 {
			inode, err = strconv.ParseInt(fields[9], 10, 64)
			if err != nil {
				continue
			}
			process, user = getProcessInfo(fields[9])
		}

		connections = append(connections, Connection{
			LocalAddr:     localAddr,
			LocalPort:     int(localPort),
			RemoteAddr:    remoteAddr,
			RemotePort:    int(remotePort),
			State:         "NONE",
			Protocol:      "udp",
			Process:       process,
			User:          user,
			Inode:         inode,
			IsTCP:         false,
			IsUDP:         true,
			IsListening:   true,
			IsEstablished: false,
		})
	}

	return connections, nil
}

// Helper functions for safe field access
func getFieldSafe(fields []string, index int) string {
	if index < len(fields) {
		return fields[index]
	}
	return ""
}

func getFieldsSafe(fields []string, startIndex int) []string {
	if startIndex < len(fields) {
		return fields[startIndex:]
	}
	return []string{}
}

func getFirewallRules() ([]FirewallRule, error) {
	var rules []FirewallRule

	// Check if we're on a platform that supports iptables
	if runtime.GOOS != "linux" {
		// Fallback to using pfctl on macOS or other platform-specific tools
		return getFirewallRulesFallback()
	}

	// Read iptables rules
	cmd := exec.Command("iptables", "-L", "-n", "-v")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to get iptables rules: %v", err)
	}

	lines := strings.Split(string(output), "\n")
	var currentChain string
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}

		if strings.HasPrefix(line, "Chain") {
			currentChain = fields[1]
			continue
		}

		if len(fields) < 8 {
			continue
		}

		// Parse rule with safe field access
		rule := FirewallRule{
			Chain:       currentChain,
			Target:      fields[0],
			Protocol:    getFieldSafe(fields, 3),
			Source:      getFieldSafe(fields, 7),
			Destination: getFieldSafe(fields, 8),
			Sport:       getFieldSafe(fields, 9),
			Dport:       getFieldSafe(fields, 10),
			Interface:   getFieldSafe(fields, 5),
			Options:     getFieldsSafe(fields, 11),
		}

		// Extract comment if present
		for i, opt := range rule.Options {
			if opt == "--comment" && i+1 < len(rule.Options) {
				rule.Comment = rule.Options[i+1]
				rule.Options = append(rule.Options[:i], rule.Options[i+2:]...)
				break
			}
		}

		rules = append(rules, rule)
	}

	return rules, nil
}

func getFirewallRulesFallback() ([]FirewallRule, error) {
	var rules []FirewallRule

	// Try pfctl on macOS with timeout
	if runtime.GOOS == "darwin" {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		cmd := exec.CommandContext(ctx, "pfctl", "-s", "rules")
		output, err := cmd.Output()
		if err == nil {
			lines := strings.Split(string(output), "\n")
			for _, line := range lines {
				if strings.TrimSpace(line) == "" {
					continue
				}

				// Parse pf rule (simplified)
				rule := FirewallRule{
					Chain:       "pf",
					Target:      "pass",
					Protocol:    "any",
					Source:      "any",
					Destination: "any",
					Sport:       "any",
					Dport:       "any",
					Interface:   "any",
					Options:     []string{line},
					Comment:     line,
				}
				rules = append(rules, rule)
			}
			return rules, nil
		}
	}

	// If no platform-specific firewall tool is available
	logger.Info("No firewall rules available on this platform")
	return rules, nil
}

func getInterfaceStats(name string) (InterfaceStats, error) {
	var stats InterfaceStats

	// Check if we're on a platform that supports /proc filesystem
	if runtime.GOOS != "linux" {
		// Fallback to using netstat or ifconfig
		return getInterfaceStatsFallback(name)
	}

	// Read /proc/net/dev
	content, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return stats, fmt.Errorf("failed to read /proc/net/dev: %v", err)
	}

	lines := strings.Split(string(content), "\n")
	for i, line := range lines {
		if i < 2 {
			continue // Skip header
		}

		fields := strings.Fields(line)
		if len(fields) < 17 {
			continue
		}

		if strings.TrimSuffix(fields[0], ":") == name {
			stats.BytesReceived, _ = strconv.ParseInt(fields[1], 10, 64)
			stats.PacketsReceived, _ = strconv.ParseInt(fields[2], 10, 64)
			stats.ErrorsReceived, _ = strconv.ParseInt(fields[3], 10, 64)
			stats.DropsReceived, _ = strconv.ParseInt(fields[4], 10, 64)
			stats.FIFOErrors, _ = strconv.ParseInt(fields[5], 10, 64)
			stats.FrameErrors, _ = strconv.ParseInt(fields[6], 10, 64)
			stats.Compressed, _ = strconv.ParseInt(fields[7], 10, 64)
			stats.Multicast, _ = strconv.ParseInt(fields[8], 10, 64)
			stats.BytesSent, _ = strconv.ParseInt(fields[9], 10, 64)
			stats.PacketsSent, _ = strconv.ParseInt(fields[10], 10, 64)
			stats.ErrorsSent, _ = strconv.ParseInt(fields[11], 10, 64)
			stats.DropsSent, _ = strconv.ParseInt(fields[12], 10, 64)
			stats.Collisions, _ = strconv.ParseInt(fields[13], 10, 64)
			stats.CarrierErrors, _ = strconv.ParseInt(fields[14], 10, 64)
			break
		}
	}

	return stats, nil
}

func getInterfaceStatsFallback(name string) (InterfaceStats, error) {
	var stats InterfaceStats

	// Try netstat -i on macOS/Unix systems with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "netstat", "-i")
	output, err := cmd.Output()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			fields := strings.Fields(line)
			if len(fields) < 8 {
				continue
			}

			// Skip header
			if fields[0] == "Name" || fields[0] == "Kernel" {
				continue
			}

			if fields[0] == name {
				// Parse basic stats (netstat format varies by platform)
				stats.PacketsReceived, _ = strconv.ParseInt(fields[3], 10, 64)
				stats.PacketsSent, _ = strconv.ParseInt(fields[5], 10, 64)
				stats.ErrorsReceived, _ = strconv.ParseInt(fields[4], 10, 64)
				stats.ErrorsSent, _ = strconv.ParseInt(fields[6], 10, 64)
				break
			}
		}
		return stats, nil
	}

	// If netstat fails, return empty stats
	logger.Debug("Unable to get interface statistics for %s on this platform", name)
	return stats, nil
}

func getInterfaceFlags(flags net.Flags) []string {
	var result []string

	if flags&net.FlagUp != 0 {
		result = append(result, "UP")
	}
	if flags&net.FlagBroadcast != 0 {
		result = append(result, "BROADCAST")
	}
	if flags&net.FlagLoopback != 0 {
		result = append(result, "LOOPBACK")
	}
	if flags&net.FlagPointToPoint != 0 {
		result = append(result, "POINTTOPOINT")
	}
	if flags&net.FlagMulticast != 0 {
		result = append(result, "MULTICAST")
	}

	return result
}

func getTCPState(state int) string {
	switch state {
	case 1:
		return "ESTABLISHED"
	case 2:
		return "SYN_SENT"
	case 3:
		return "SYN_RECV"
	case 4:
		return "FIN_WAIT1"
	case 5:
		return "FIN_WAIT2"
	case 6:
		return "TIME_WAIT"
	case 7:
		return "CLOSE"
	case 8:
		return "CLOSE_WAIT"
	case 9:
		return "LAST_ACK"
	case 10:
		return "LISTEN"
	case 11:
		return "CLOSING"
	default:
		return "UNKNOWN"
	}
}

func getServiceName(port int, protocol string) string {
	// Read /etc/services
	content, err := os.ReadFile("/etc/services")
	if err != nil {
		return ""
	}

	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		// Parse port number
		portStr := strings.Split(fields[1], "/")[0]
		servicePort, err := strconv.Atoi(portStr)
		if err != nil {
			continue
		}

		// Check if port and protocol match
		if servicePort == port && strings.HasSuffix(fields[1], "/"+protocol) {
			return fields[0]
		}
	}

	return ""
}

func getProcessInfo(_ string) (string, string) {
	// Read /proc/net/tcp and /proc/net/udp to find the process
	// This is a simplified version - in reality, you'd need to check /proc/*/fd
	return "", ""
}
