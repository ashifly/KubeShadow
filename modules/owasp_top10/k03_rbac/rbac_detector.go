package rbac

import (
	"context"
	"fmt"
	"time"

	"kubeshadow/pkg/logger"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// NewRBACScanner creates a new RBAC scanner
func NewRBACScanner(ctx context.Context, kubeconfig string) (*RBACScanner, error) {
	config, err := getKubeConfig(kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("failed to get kubeconfig: %w", err)
	}

	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create kubernetes client: %w", err)
	}

	return &RBACScanner{
		client: client,
		ctx:    ctx,
	}, nil
}

// CollectRBACData collects all RBAC-related resources
func (s *RBACScanner) CollectRBACData(namespace string) (*RBACData, error) {
	logger.Info("🔍 Collecting RBAC data...")

	data := &RBACData{
		CollectedAt: time.Now(),
	}

	// Collect Roles
	if namespace == "" {
		// Collect from all namespaces
		roles, err := s.client.RbacV1().Roles("").List(s.ctx, metav1.ListOptions{})
		if err != nil {
			return nil, fmt.Errorf("failed to list roles: %w", err)
		}
		data.Roles = roles.Items
	} else {
		roles, err := s.client.RbacV1().Roles(namespace).List(s.ctx, metav1.ListOptions{})
		if err != nil {
			return nil, fmt.Errorf("failed to list roles in namespace %s: %w", namespace, err)
		}
		data.Roles = roles.Items
	}

	// Collect ClusterRoles
	clusterRoles, err := s.client.RbacV1().ClusterRoles().List(s.ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list cluster roles: %w", err)
	}
	data.ClusterRoles = clusterRoles.Items

	// Collect RoleBindings
	if namespace == "" {
		roleBindings, err := s.client.RbacV1().RoleBindings("").List(s.ctx, metav1.ListOptions{})
		if err != nil {
			return nil, fmt.Errorf("failed to list role bindings: %w", err)
		}
		data.RoleBindings = roleBindings.Items
	} else {
		roleBindings, err := s.client.RbacV1().RoleBindings(namespace).List(s.ctx, metav1.ListOptions{})
		if err != nil {
			return nil, fmt.Errorf("failed to list role bindings in namespace %s: %w", namespace, err)
		}
		data.RoleBindings = roleBindings.Items
	}

	// Collect ClusterRoleBindings
	clusterRoleBindings, err := s.client.RbacV1().ClusterRoleBindings().List(s.ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list cluster role bindings: %w", err)
	}
	data.ClusterRoleBindings = clusterRoleBindings.Items

	// Collect ServiceAccounts
	if namespace == "" {
		serviceAccounts, err := s.client.CoreV1().ServiceAccounts("").List(s.ctx, metav1.ListOptions{})
		if err != nil {
			return nil, fmt.Errorf("failed to list service accounts: %w", err)
		}
		data.ServiceAccounts = serviceAccounts.Items
	} else {
		serviceAccounts, err := s.client.CoreV1().ServiceAccounts(namespace).List(s.ctx, metav1.ListOptions{})
		if err != nil {
			return nil, fmt.Errorf("failed to list service accounts in namespace %s: %w", namespace, err)
		}
		data.ServiceAccounts = serviceAccounts.Items
	}

	logger.Info("📊 RBAC Data Collection Summary:")
	logger.Info("   Roles: %d", len(data.Roles))
	logger.Info("   ClusterRoles: %d", len(data.ClusterRoles))
	logger.Info("   RoleBindings: %d", len(data.RoleBindings))
	logger.Info("   ClusterRoleBindings: %d", len(data.ClusterRoleBindings))
	logger.Info("   ServiceAccounts: %d", len(data.ServiceAccounts))

	return data, nil
}

// BuildGraph builds the RBAC graph from collected data
func (s *RBACScanner) BuildGraph(data *RBACData) *RBACGraph {
	logger.Info("🕸️  Building RBAC graph...")

	graph := &RBACGraph{
		Nodes: []GraphNode{},
		Edges: []GraphEdge{},
	}

	// Add nodes for subjects (ServiceAccounts, Users, Groups)
	subjectMap := make(map[string]bool)

	// Process ServiceAccounts
	for _, sa := range data.ServiceAccounts {
		subjectID := fmt.Sprintf("sa:%s:%s", sa.Namespace, sa.Name)
		if !subjectMap[subjectID] {
			graph.Nodes = append(graph.Nodes, GraphNode{
				ID:        subjectID,
				Type:      "subject",
				Name:      sa.Name,
				Namespace: sa.Namespace,
				Metadata: map[string]interface{}{
					"kind": "ServiceAccount",
				},
			})
			subjectMap[subjectID] = true
		}
	}

	// Process RoleBindings
	for _, rb := range data.RoleBindings {
		roleID := fmt.Sprintf("role:%s:%s", rb.Namespace, rb.RoleRef.Name)

		// Add role node
		graph.Nodes = append(graph.Nodes, GraphNode{
			ID:        roleID,
			Type:      "resource",
			Name:      rb.RoleRef.Name,
			Namespace: rb.Namespace,
			Metadata: map[string]interface{}{
				"kind": "Role",
			},
		})

		// Add edges from subjects to roles
		for _, subject := range rb.Subjects {
			subjectID := s.getSubjectID(subject, rb.Namespace)
			if subjectID != "" {
				graph.Edges = append(graph.Edges, GraphEdge{
					From:     subjectID,
					To:       roleID,
					Verb:     "bind",
					Resource: "roles",
					Weight:   1,
				})
			}
		}
	}

	// Process ClusterRoleBindings
	for _, crb := range data.ClusterRoleBindings {
		roleID := fmt.Sprintf("clusterrole:%s", crb.RoleRef.Name)

		// Add cluster role node
		graph.Nodes = append(graph.Nodes, GraphNode{
			ID:   roleID,
			Type: "resource",
			Name: crb.RoleRef.Name,
			Metadata: map[string]interface{}{
				"kind": "ClusterRole",
			},
		})

		// Add edges from subjects to cluster roles
		for _, subject := range crb.Subjects {
			subjectID := s.getSubjectID(subject, "")
			if subjectID != "" {
				graph.Edges = append(graph.Edges, GraphEdge{
					From:     subjectID,
					To:       roleID,
					Verb:     "bind",
					Resource: "clusterroles",
					Weight:   1,
				})
			}
		}
	}

	// Add permission edges from roles to resources
	s.addPermissionEdges(graph, data)

	logger.Info("📊 Graph built: %d nodes, %d edges", len(graph.Nodes), len(graph.Edges))
	return graph
}

// addPermissionEdges adds edges representing permissions
func (s *RBACScanner) addPermissionEdges(graph *RBACGraph, data *RBACData) {
	// Process Roles
	for _, role := range data.Roles {
		roleID := fmt.Sprintf("role:%s:%s", role.Namespace, role.Name)

		for _, rule := range role.Rules {
			for _, resource := range rule.Resources {
				for _, verb := range rule.Verbs {
					resourceID := fmt.Sprintf("resource:%s:%s", rule.APIGroups[0], resource)

					// Add resource node
					graph.Nodes = append(graph.Nodes, GraphNode{
						ID:   resourceID,
						Type: "resource",
						Name: resource,
						Metadata: map[string]interface{}{
							"apiGroup": rule.APIGroups[0],
							"kind":     "Resource",
						},
					})

					// Add edge from role to resource
					graph.Edges = append(graph.Edges, GraphEdge{
						From:     roleID,
						To:       resourceID,
						Verb:     verb,
						Resource: resource,
						Weight:   s.getVerbWeight(verb),
					})
				}
			}
		}
	}

	// Process ClusterRoles
	for _, clusterRole := range data.ClusterRoles {
		roleID := fmt.Sprintf("clusterrole:%s", clusterRole.Name)

		for _, rule := range clusterRole.Rules {
			for _, resource := range rule.Resources {
				for _, verb := range rule.Verbs {
					resourceID := fmt.Sprintf("resource:%s:%s", rule.APIGroups[0], resource)

					// Add edge from cluster role to resource
					graph.Edges = append(graph.Edges, GraphEdge{
						From:     roleID,
						To:       resourceID,
						Verb:     verb,
						Resource: resource,
						Weight:   s.getVerbWeight(verb),
					})
				}
			}
		}
	}
}

// getSubjectID returns a unique ID for a subject
func (s *RBACScanner) getSubjectID(subject rbacv1.Subject, defaultNamespace string) string {
	switch subject.Kind {
	case "ServiceAccount":
		ns := subject.Namespace
		if ns == "" {
			ns = defaultNamespace
		}
		return fmt.Sprintf("sa:%s:%s", ns, subject.Name)
	case "User":
		return fmt.Sprintf("user:%s", subject.Name)
	case "Group":
		return fmt.Sprintf("group:%s", subject.Name)
	default:
		return ""
	}
}

// getVerbWeight returns the weight of a verb for path scoring
func (s *RBACScanner) getVerbWeight(verb string) int {
	switch verb {
	case "create", "delete", "patch", "update":
		return 3
	case "get", "list", "watch":
		return 1
	case "*":
		return 5
	default:
		return 2
	}
}

// getKubeConfig creates a Kubernetes config
func getKubeConfig(kubeconfig string) (*rest.Config, error) {
	if kubeconfig != "" {
		return clientcmd.BuildConfigFromFlags("", kubeconfig)
	}
	return rest.InClusterConfig()
}
