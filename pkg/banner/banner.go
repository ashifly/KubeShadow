package banner

import (
	"fmt"
	"strings"
)

const (
	Version = "v0.1.0"
	banner  = `
██╗  ██╗██╗   ██╗██████╗ ███████╗███████╗██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗    ██╗
██║ ██╔╝██║   ██║██╔══██╗██╔════╝██╔════╝██║  ██║██╔══██╗██╔══██╗██╔═══██╗██║    ██║
█████╔╝ ██║   ██║██████╔╝█████╗  ███████╗███████║███████║██║  ██║██║   ██║██║ █╗ ██║
██╔═██╗ ██║   ██║██╔══██╗██╔══╝  ╚════██║██╔══██║██╔══██║██║  ██║██║   ██║██║███╗██║
██║  ██╗╚██████╔╝██████╔╝███████╗███████║██║  ██║██║  ██║██████╔╝╚██████╔╝╚███╔███╔╝
╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚══╝╚══╝
`
	tagline = "🕵️  Kubernetes Security Testing & Assessment Tool"
	author  = "by ashifly"
)

// Print displays the banner with version and tagline
func Print() {
	// Print banner in cyan
	fmt.Printf("\033[36m%s\033[0m", banner)

	// Add separator line
	fmt.Println("\033[36m" + strings.Repeat("─", 80) + "\033[0m")

	// Print version in yellow
	fmt.Printf("\033[33mVersion %s\033[0m\n", Version)

	// Print tagline and author on the same line
	fmt.Printf("%s \033[35m%s\033[0m\n\n", tagline, author)
}

// PrintModule displays which module is being run
func PrintModule(moduleName string) {
	fmt.Printf("🚀 Running module: \033[1;32m%s\033[0m\n\n", moduleName)
}
