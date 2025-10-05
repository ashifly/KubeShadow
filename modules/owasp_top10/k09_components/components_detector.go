package k09_components

import (
	"context"
	"fmt"
	"strings"
	"time"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// NewComponentScanner creates a new component scanner
func NewComponentScanner(kubeconfig string, namespace string, labMode bool) (*ComponentScanner, error) {
	var config *rest.Config
	var err error

	if kubeconfig != "" {
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
	} else {
		config, err = rest.InClusterConfig()
		if err != nil {
			config, err = clientcmd.BuildConfigFromFlags("", clientcmd.RecommendedHomeFile)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("failed to create kubeconfig: %w", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create kubernetes client: %w", err)
	}

	return &ComponentScanner{
		client:    clientset,
		namespace: namespace,
		ctx:       context.Background(),
		labMode:   labMode,
	}, nil
}

// DetectWebhooks detects webhook configurations
func (cs *ComponentScanner) DetectWebhooks() ([]WebhookInfo, []ComponentFinding, error) {
	var findings []ComponentFinding
	var webhooks []WebhookInfo

	// Detect MutatingWebhookConfigurations
	mutatingWebhooks, mutatingFindings, err := cs.detectMutatingWebhooks()
	if err != nil {
		return webhooks, findings, fmt.Errorf("failed to detect mutating webhooks: %w", err)
	}
	webhooks = append(webhooks, mutatingWebhooks...)
	findings = append(findings, mutatingFindings...)

	// Detect ValidatingWebhookConfigurations
	validatingWebhooks, validatingFindings, err := cs.detectValidatingWebhooks()
	if err != nil {
		return webhooks, findings, fmt.Errorf("failed to detect validating webhooks: %w", err)
	}
	webhooks = append(webhooks, validatingWebhooks...)
	findings = append(findings, validatingFindings...)

	return webhooks, findings, nil
}

// detectMutatingWebhooks detects MutatingWebhookConfigurations
func (cs *ComponentScanner) detectMutatingWebhooks() ([]WebhookInfo, []ComponentFinding, error) {
	var findings []ComponentFinding
	var webhooks []WebhookInfo

	// List MutatingWebhookConfigurations
	mutatingWebhookList, err := cs.client.AdmissionregistrationV1().MutatingWebhookConfigurations().List(cs.ctx, metav1.ListOptions{})
	if err != nil {
		return webhooks, findings, fmt.Errorf("failed to list mutating webhook configurations: %w", err)
	}

	for _, mwc := range mutatingWebhookList.Items {
		for _, webhook := range mwc.Webhooks {
			webhookInfo := WebhookInfo{
				Name:      webhook.Name,
				Namespace: "", // MutatingWebhookConfigurations are cluster-scoped
				Type:      "MutatingWebhook",
				Metadata:  make(map[string]string),
			}

			// Extract webhook details
			if webhook.ClientConfig.Service != nil {
				webhookInfo.ServiceName = webhook.ClientConfig.Service.Name
				webhookInfo.ServiceNamespace = webhook.ClientConfig.Service.Namespace
				webhookInfo.ServicePath = *webhook.ClientConfig.Service.Path
			}

			// Check CABundle
			if len(webhook.ClientConfig.CABundle) == 0 {
				webhookInfo.RiskLevel = "high"
				findings = append(findings, ComponentFinding{
					ID:          "component-001",
					Type:        "webhook-cabundle",
					Severity:    "high",
					Title:       "Webhook Missing CABundle",
					Description: fmt.Sprintf("MutatingWebhook %s has no CABundle configured.", webhook.Name),
					Resource:    fmt.Sprintf("mutatingwebhookconfiguration/%s", mwc.Name),
					Namespace:   "",
					RiskScore:   8.0,
					Remediation: "Configure CABundle for webhook to ensure secure communication.",
					Timestamp:   time.Now(),
					Metadata: map[string]string{
						"webhook_name": webhook.Name,
						"webhook_type": "MutatingWebhook",
					},
				})
			} else {
				webhookInfo.CABundle = "configured"
			}

			// Check failure policy
			if webhook.FailurePolicy != nil && *webhook.FailurePolicy == admissionregistrationv1.Ignore {
				webhookInfo.FailurePolicy = "Ignore"
				webhookInfo.RiskLevel = "medium"
				findings = append(findings, ComponentFinding{
					ID:          "component-002",
					Type:        "webhook-failure-policy",
					Severity:    "medium",
					Title:       "Webhook with Ignore Failure Policy",
					Description: fmt.Sprintf("MutatingWebhook %s has failurePolicy set to Ignore.", webhook.Name),
					Resource:    fmt.Sprintf("mutatingwebhookconfiguration/%s", mwc.Name),
					Namespace:   "",
					RiskScore:   6.0,
					Remediation: "Consider using Fail failure policy for better security.",
					Timestamp:   time.Now(),
					Metadata: map[string]string{
						"webhook_name":   webhook.Name,
						"failure_policy": "Ignore",
					},
				})
			} else if webhook.FailurePolicy != nil {
				webhookInfo.FailurePolicy = string(*webhook.FailurePolicy)
			}

			// Extract rules
			for _, rule := range webhook.Rules {
				webhookRule := WebhookRule{
					APIGroups:   rule.APIGroups,
					APIVersions: rule.APIVersions,
					Resources:   rule.Resources,
					Operations:  []string{},
					Scope:       string(*rule.Scope),
				}

				for _, op := range rule.Operations {
					webhookRule.Operations = append(webhookRule.Operations, string(op))
				}

				webhookInfo.Rules = append(webhookInfo.Rules, webhookRule)
			}

			// Check namespace selector
			if webhook.NamespaceSelector != nil {
				webhookInfo.NamespaceSelector = &NamespaceSelector{
					MatchLabels: webhook.NamespaceSelector.MatchLabels,
				}
			}

			// Check object selector
			if webhook.ObjectSelector != nil {
				webhookInfo.ObjectSelector = &ObjectSelector{
					MatchLabels: webhook.ObjectSelector.MatchLabels,
				}
			}

			// Check admission review versions
			webhookInfo.AdmissionReviewVersions = webhook.AdmissionReviewVersions

			webhooks = append(webhooks, webhookInfo)
		}
	}

	return webhooks, findings, nil
}

// detectValidatingWebhooks detects ValidatingWebhookConfigurations
func (cs *ComponentScanner) detectValidatingWebhooks() ([]WebhookInfo, []ComponentFinding, error) {
	var findings []ComponentFinding
	var webhooks []WebhookInfo

	// List ValidatingWebhookConfigurations
	validatingWebhookList, err := cs.client.AdmissionregistrationV1().ValidatingWebhookConfigurations().List(cs.ctx, metav1.ListOptions{})
	if err != nil {
		return webhooks, findings, fmt.Errorf("failed to list validating webhook configurations: %w", err)
	}

	for _, vwc := range validatingWebhookList.Items {
		for _, webhook := range vwc.Webhooks {
			webhookInfo := WebhookInfo{
				Name:      webhook.Name,
				Namespace: "", // ValidatingWebhookConfigurations are cluster-scoped
				Type:      "ValidatingWebhook",
				Metadata:  make(map[string]string),
			}

			// Extract webhook details
			if webhook.ClientConfig.Service != nil {
				webhookInfo.ServiceName = webhook.ClientConfig.Service.Name
				webhookInfo.ServiceNamespace = webhook.ClientConfig.Service.Namespace
				webhookInfo.ServicePath = *webhook.ClientConfig.Service.Path
			}

			// Check CABundle
			if len(webhook.ClientConfig.CABundle) == 0 {
				webhookInfo.RiskLevel = "high"
				findings = append(findings, ComponentFinding{
					ID:          "component-003",
					Type:        "webhook-cabundle",
					Severity:    "high",
					Title:       "Webhook Missing CABundle",
					Description: fmt.Sprintf("ValidatingWebhook %s has no CABundle configured.", webhook.Name),
					Resource:    fmt.Sprintf("validatingwebhookconfiguration/%s", vwc.Name),
					Namespace:   "",
					RiskScore:   8.0,
					Remediation: "Configure CABundle for webhook to ensure secure communication.",
					Timestamp:   time.Now(),
					Metadata: map[string]string{
						"webhook_name": webhook.Name,
						"webhook_type": "ValidatingWebhook",
					},
				})
			} else {
				webhookInfo.CABundle = "configured"
			}

			// Check failure policy
			if webhook.FailurePolicy != nil && *webhook.FailurePolicy == admissionregistrationv1.Ignore {
				webhookInfo.FailurePolicy = "Ignore"
				webhookInfo.RiskLevel = "medium"
				findings = append(findings, ComponentFinding{
					ID:          "component-004",
					Type:        "webhook-failure-policy",
					Severity:    "medium",
					Title:       "Webhook with Ignore Failure Policy",
					Description: fmt.Sprintf("ValidatingWebhook %s has failurePolicy set to Ignore.", webhook.Name),
					Resource:    fmt.Sprintf("validatingwebhookconfiguration/%s", vwc.Name),
					Namespace:   "",
					RiskScore:   6.0,
					Remediation: "Consider using Fail failure policy for better security.",
					Timestamp:   time.Now(),
					Metadata: map[string]string{
						"webhook_name":   webhook.Name,
						"failure_policy": "Ignore",
					},
				})
			} else if webhook.FailurePolicy != nil {
				webhookInfo.FailurePolicy = string(*webhook.FailurePolicy)
			}

			// Extract rules
			for _, rule := range webhook.Rules {
				webhookRule := WebhookRule{
					APIGroups:   rule.APIGroups,
					APIVersions: rule.APIVersions,
					Resources:   rule.Resources,
					Operations:  []string{},
					Scope:       string(*rule.Scope),
				}

				for _, op := range rule.Operations {
					webhookRule.Operations = append(webhookRule.Operations, string(op))
				}

				webhookInfo.Rules = append(webhookInfo.Rules, webhookRule)
			}

			// Check namespace selector
			if webhook.NamespaceSelector != nil {
				webhookInfo.NamespaceSelector = &NamespaceSelector{
					MatchLabels: webhook.NamespaceSelector.MatchLabels,
				}
			}

			// Check object selector
			if webhook.ObjectSelector != nil {
				webhookInfo.ObjectSelector = &ObjectSelector{
					MatchLabels: webhook.ObjectSelector.MatchLabels,
				}
			}

			// Check admission review versions
			webhookInfo.AdmissionReviewVersions = webhook.AdmissionReviewVersions

			webhooks = append(webhooks, webhookInfo)
		}
	}

	return webhooks, findings, nil
}

// DetectCRDs detects Custom Resource Definitions
func (cs *ComponentScanner) DetectCRDs() ([]CRDInfo, []ComponentFinding, error) {
	var findings []ComponentFinding
	var crds []CRDInfo

	// For now, we'll simulate CRD detection since we don't have the apiextensions client
	// In a real implementation, you would use the apiextensions client
	// This is a simplified version for demonstration

	// Simulate some CRDs
	simulatedCRDs := []CRDInfo{
		{
			Name:      "risky-crd-1",
			Group:     "example.com",
			Version:   "v1",
			Scope:     "Cluster",
			RiskLevel: "high",
			Metadata:  make(map[string]string),
		},
		{
			Name:      "safe-crd-1",
			Group:     "example.com",
			Version:   "v1",
			Scope:     "Namespaced",
			RiskLevel: "low",
			Metadata:  make(map[string]string),
		},
	}

	for _, crd := range simulatedCRDs {
		if crd.RiskLevel == "high" {
			findings = append(findings, ComponentFinding{
				ID:          "component-005",
				Type:        "risky-crd",
				Severity:    "high",
				Title:       "Risky Custom Resource Definition",
				Description: fmt.Sprintf("CRD %s exposes risky functionality.", crd.Name),
				Resource:    fmt.Sprintf("customresourcedefinition/%s", crd.Name),
				Namespace:   "",
				RiskScore:   7.5,
				Remediation: "Review CRD permissions and restrict access to sensitive operations.",
				Timestamp:   time.Now(),
				Metadata: map[string]string{
					"crd_name":  crd.Name,
					"crd_group": crd.Group,
				},
			})
		}
		crds = append(crds, crd)
	}

	return crds, findings, nil
}

// DetectControllers detects controller components
func (cs *ComponentScanner) DetectControllers() ([]ControllerInfo, []ComponentFinding, error) {
	var findings []ComponentFinding
	var controllers []ControllerInfo

	// List deployments in kube-system namespace
	deployments, err := cs.client.AppsV1().Deployments("kube-system").List(cs.ctx, metav1.ListOptions{})
	if err != nil {
		return controllers, findings, fmt.Errorf("failed to list deployments: %w", err)
	}

	for _, deployment := range deployments.Items {
		controller := ControllerInfo{
			Name:      deployment.Name,
			Namespace: deployment.Namespace,
			Type:      "Deployment",
			Metadata:  make(map[string]string),
		}

		// Extract image information
		if len(deployment.Spec.Template.Spec.Containers) > 0 {
			container := deployment.Spec.Template.Spec.Containers[0]
			controller.Image = container.Image
			controller.Version = cs.extractVersionFromImage(container.Image)
		}

		// Check if controller is outdated
		if cs.isOutdatedController(controller) {
			controller.Outdated = true
			controller.RiskLevel = "medium"
			findings = append(findings, ComponentFinding{
				ID:          "component-006",
				Type:        "outdated-controller",
				Severity:    "medium",
				Title:       "Outdated Controller",
				Description: fmt.Sprintf("Controller %s is using an outdated version.", deployment.Name),
				Resource:    fmt.Sprintf("deployment/%s", deployment.Name),
				Namespace:   deployment.Namespace,
				RiskScore:   6.5,
				Remediation: "Update controller to the latest version.",
				Timestamp:   time.Now(),
				Metadata: map[string]string{
					"controller_name": deployment.Name,
					"controller_type": "Deployment",
					"image":           controller.Image,
				},
			})
		}

		controllers = append(controllers, controller)
	}

	return controllers, findings, nil
}

// Helper methods for component detection

func (cs *ComponentScanner) isOutdatedController(controller ControllerInfo) bool {
	// This is a simplified check - in reality, you'd compare against known versions
	outdatedPatterns := []string{
		"v1.0", "v1.1", "v1.2", "v1.3", "v1.4", "v1.5",
		"v1.6", "v1.7", "v1.8", "v1.9", "v1.10",
	}

	version := strings.ToLower(controller.Version)
	for _, pattern := range outdatedPatterns {
		if strings.Contains(version, pattern) {
			return true
		}
	}

	return false
}

func (cs *ComponentScanner) extractVersionFromImage(image string) string {
	// Extract version from image tag
	parts := strings.Split(image, ":")
	if len(parts) > 1 {
		return parts[len(parts)-1]
	}
	return "latest"
}
