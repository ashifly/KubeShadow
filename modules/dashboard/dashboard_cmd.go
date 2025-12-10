package dashboard_cmd

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	"kubeshadow/pkg/dashboard"

	"github.com/spf13/cobra"
)

// getNetworkIPs returns all non-loopback IP addresses for the machine
func getNetworkIPs() []string {
	var ips []string
	
	// Get all network interfaces
	interfaces, err := net.Interfaces()
	if err != nil {
		return ips
	}
	
	for _, iface := range interfaces {
		// Skip loopback and down interfaces
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			
			if ip == nil || ip.IsLoopback() {
				continue
			}
			
			// Only include IPv4 addresses
			if ip.To4() != nil {
				ips = append(ips, ip.String())
			}
		}
	}
	
	// Remove duplicates
	seen := make(map[string]bool)
	var uniqueIPs []string
	for _, ip := range ips {
		if !seen[ip] {
			seen[ip] = true
			uniqueIPs = append(uniqueIPs, ip)
		}
	}
	
	return uniqueIPs
}

var DashboardCmd = &cobra.Command{
	Use:   "dashboard",
	Short: "Start the KubeShadow web dashboard",
	Long:  "Start the web dashboard to monitor KubeShadow command executions in real-time",
	RunE: func(cmd *cobra.Command, args []string) error {
		port, err := cmd.Flags().GetInt("port")
		if err != nil {
			return fmt.Errorf("failed to get port flag: %w", err)
		}

		background, err := cmd.Flags().GetBool("background")
		if err != nil {
			return fmt.Errorf("failed to get background flag: %w", err)
		}

		dashboardInstance := dashboard.GetInstance()
		
		if err := dashboardInstance.Start(port); err != nil {
			return fmt.Errorf("failed to start dashboard: %w", err)
		}

		// Get network IPs for display
		ips := getNetworkIPs()
		fmt.Printf("🎯 KubeShadow Dashboard started on http://localhost:%d\n", port)
		if len(ips) > 0 {
			fmt.Println("🌐 Accessible from network:")
			for _, ip := range ips {
				fmt.Printf("   http://%s:%d\n", ip, port)
			}
		}
		
		// Show SSH port forwarding instructions for remote access
		fmt.Println("\n📡 For SSH/Remote Access:")
		fmt.Printf("   Local port forward: ssh -L %d:localhost:%d user@host\n", port, port)
		fmt.Println("   Then access: http://localhost:" + fmt.Sprintf("%d", port))
		fmt.Println("   Or use GCP Console port forwarding feature")
		
		fmt.Println("\n📊 Use the --dashboard flag with other commands to publish results here")
		
		if background {
			fmt.Println("✅ Dashboard running in background")
			fmt.Println("💡 To stop: ./kubeshadow dashboard stop")
			// Return immediately, dashboard runs in background
			return nil
		}

		fmt.Println("Press Ctrl+C to stop the dashboard")

		// Wait for interrupt signal
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt, syscall.SIGTERM)
		<-c

		fmt.Println("\nShutting down dashboard...")
		return dashboardInstance.Stop()
	},
}

func init() {
	DashboardCmd.Flags().Int("port", 8080, "Port for the dashboard web server")
	DashboardCmd.Flags().Bool("background", false, "Run dashboard in background (non-blocking)")
}
