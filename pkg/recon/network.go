package recon

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"

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

func getConnections() ([]Connection, error) {
	var connections []Connection

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

func getFirewallRules() ([]FirewallRule, error) {
	var rules []FirewallRule

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

		// Parse rule
		rule := FirewallRule{
			Chain:       currentChain,
			Target:      fields[0],
			Protocol:    fields[3],
			Source:      fields[7],
			Destination: fields[8],
			Sport:       fields[9],
			Dport:       fields[10],
			Interface:   fields[5],
			Options:     fields[11:],
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

func getInterfaceStats(name string) (InterfaceStats, error) {
	var stats InterfaceStats

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

func getProcessInfo(inode string) (string, string) {
	// Read /proc/net/tcp and /proc/net/udp to find the process
	// This is a simplified version - in reality, you'd need to check /proc/*/fd
	return "", ""
}
