package multi_cloud

import (
	"context"
	"fmt"

	"kubeshadow/pkg/errors"
	"kubeshadow/pkg/logger"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	stsTypes "github.com/aws/aws-sdk-go-v2/service/sts/types" // Import the types package
	"github.com/spf13/cobra"
)

var (
	// AssumeRoleAbuseCmd represents the command for the Assume Role Abuse module
	AssumeRoleAbuseCmd = &cobra.Command{
		Use:   "assume-role-abuse",
		Short: "Attempt to assume an AWS IAM role",
		Long:  `Attempts to assume a specified AWS IAM role using available credentials (e.g., environment variables, shared credential file, EC2 instance profile). Requires AWS SDK compatible credentials to be configured.`, // Added Long description
		RunE: func(cmd *cobra.Command, args []string) error {
			// Get flag values
			targetRoleArn, _ := cmd.Flags().GetString("role-arn")
			sessionName, _ := cmd.Flags().GetString("session-name")

			// Basic validation (MarkFlagRequired also handles this)
			if targetRoleArn == "" || sessionName == "" {
				return errors.New(errors.ErrValidation, "required flags --role-arn and --session-name are missing", nil)
			}

			// Execute the core logic
			credentials, err := runAssumeRoleLogic(cmd.Context(), targetRoleArn, sessionName)
			if err != nil {
				return err // runAssumeRoleLogic returns KubeShadow errors
			}

			// Print assumed credentials (be cautious with displaying sensitive info)
			logger.Info("Role assumed successfully!")
			logger.Info("  Access Key ID: %s", *credentials.AccessKeyId)
			logger.Info("  Secret Access Key: %s", *credentials.SecretAccessKey)
			logger.Info("  Session Token: %s", *credentials.SessionToken) // Session tokens can be very long

			return nil
		},
	}
)

func init() {
	// Define flags for the command
	AssumeRoleAbuseCmd.Flags().String("role-arn", "", "The ARN of the role to assume")
	AssumeRoleAbuseCmd.Flags().String("session-name", "kubeshadow-session", "An identifier for the assumed role session")

	// Mark flags as required
	AssumeRoleAbuseCmd.MarkFlagRequired("role-arn")
	AssumeRoleAbuseCmd.MarkFlagRequired("session-name")
}

// runAssumeRoleLogic contains the core logic for assuming an AWS IAM role
// Returns the specific STS Credentials type
func runAssumeRoleLogic(ctx context.Context, targetRoleArn string, sessionName string) (*stsTypes.Credentials, error) {
	logger.Info("Loading AWS credentials from current environment...")

	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, errors.New(errors.ErrCloud, fmt.Sprintf("unable to load AWS config: %v", err), err)
	}

	client := sts.NewFromConfig(cfg)

	logger.Info("Attempting to assume role: %s", targetRoleArn)

	input := &sts.AssumeRoleInput{
		RoleArn:         aws.String(targetRoleArn),
		RoleSessionName: aws.String(sessionName),
		DurationSeconds: aws.Int32(3600), // Default to 1 hour
	}

	output, err := client.AssumeRole(ctx, input)
	if err != nil {
		return nil, errors.New(errors.ErrCloud, fmt.Sprintf("assume role failed for role %s: %v", targetRoleArn, err), err)
	}

	return output.Credentials, nil
}
