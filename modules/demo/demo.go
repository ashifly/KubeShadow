package demo

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"
)

var DemoCmd = &cobra.Command{
	Use:   "demo",
	Short: "Demo command to test dashboard functionality",
	Long:  "A demo command that simulates various operations to test the dashboard publishing feature",
	RunE: func(cmd *cobra.Command, args []string) error {
		// Execute demo
		duration, _ := cmd.Flags().GetInt("duration")
		fail, _ := cmd.Flags().GetBool("fail")

		fmt.Println("🚀 Starting KubeShadow Demo Command")
		fmt.Printf("⏱️  Duration: %d seconds\n", duration)
		fmt.Printf("❌ Fail mode: %t\n", fail)

		// Simulate some work
		for i := 1; i <= duration; i++ {
			fmt.Printf("📋 Step %d/%d: Processing...\n", i, duration)
			time.Sleep(1 * time.Second)
		}

		if fail {
			return fmt.Errorf("demo command failed as requested")
		}

		fmt.Println("✅ Demo command completed successfully!")
		return nil
	},
}

func init() {
	DemoCmd.Flags().Int("duration", 3, "Duration of the demo in seconds")
	DemoCmd.Flags().Bool("fail", false, "Make the demo command fail")
}
