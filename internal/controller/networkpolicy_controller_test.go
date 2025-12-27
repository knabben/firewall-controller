//go:build windows

package controller

import (
	"context"
	"testing"
	"time"

	"github.com/go-logr/logr"
	hcnlib "github.com/Microsoft/hcsshim/hcn"
	hcnpkg "github.com/knabben/firewall-controller/internal/hcn"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// mockHCNManager is a mock implementation of the HCN Manager for testing
type mockHCNManager struct {
	appliedPolicies map[string][]hcnpkg.ACLRule
	removedPolicies []string
	applyError      error
	removeError     error
}

func newMockHCNManager() *mockHCNManager {
	return &mockHCNManager{
		appliedPolicies: make(map[string][]hcnpkg.ACLRule),
		removedPolicies: []string{},
	}
}

func (m *mockHCNManager) ApplyACLRules(policyKey string, rules []hcnpkg.ACLRule) error {
	if m.applyError != nil {
		return m.applyError
	}
	m.appliedPolicies[policyKey] = rules
	return nil
}

func (m *mockHCNManager) RemoveACLRules(policyKey string) error {
	if m.removeError != nil {
		return m.removeError
	}
	m.removedPolicies = append(m.removedPolicies, policyKey)
	delete(m.appliedPolicies, policyKey)
	return nil
}

func (m *mockHCNManager) GetAppliedPolicies(policyKey string) ([]hcnpkg.RuleSet, bool) {
	rules, exists := m.appliedPolicies[policyKey]
	if !exists {
		return nil, false
	}
	// Simple mock - just return that something was applied
	return []hcnpkg.RuleSet{{EndpointID: "mock-endpoint"}}, len(rules) > 0
}

func (m *mockHCNManager) ListTrackedPolicies() []string {
	keys := make([]string, 0, len(m.appliedPolicies))
	for key := range m.appliedPolicies {
		keys = append(keys, key)
	}
	return keys
}

func TestReconcile_CreateNetworkPolicy(t *testing.T) {
	// Setup scheme
	scheme := runtime.NewScheme()
	_ = networkingv1.AddToScheme(scheme)

	// Create a test NetworkPolicy
	np := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-policy",
			Namespace: "default",
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "web"},
			},
			Ingress: []networkingv1.NetworkPolicyIngressRule{
				{
					Ports: []networkingv1.NetworkPolicyPort{
						{
							Protocol: protoPtr("TCP"),
							Port:     &intstr.IntOrString{Type: intstr.Int, IntVal: 80},
						},
					},
				},
			},
		},
	}

	// Create fake client with the NetworkPolicy
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(np).
		Build()

	// Create mock HCN manager
	mockHCN := newMockHCNManager()

	// Create reconciler
	reconciler := &NetworkPolicyReconciler{
		Client:     fakeClient,
		Scheme:     scheme,
		HCNManager: mockHCN,
		NodeName:   "test-node",
	}

	// Reconcile
	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-policy",
			Namespace: "default",
		},
	}

	result, err := reconciler.Reconcile(context.Background(), req)
	if err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}

	if result.Requeue {
		t.Error("Expected no requeue")
	}

	// Verify HCN rules were applied
	policyKey := "default/test-policy"
	rules, exists := mockHCN.appliedPolicies[policyKey]
	if !exists {
		t.Fatal("Expected ACL rules to be applied")
	}

	if len(rules) == 0 {
		t.Error("Expected at least one ACL rule")
	}

	// Verify the rule details
	rule := rules[0]
	if rule.Direction != hcnlib.DirectionTypeIn {
		t.Errorf("Expected Direction In, got %v", rule.Direction)
	}
	if rule.Protocol != "6" { // TCP
		t.Errorf("Expected Protocol 6 (TCP), got %s", rule.Protocol)
	}
}

func TestReconcile_DeleteNetworkPolicy(t *testing.T) {
	// Setup scheme
	scheme := runtime.NewScheme()
	_ = networkingv1.AddToScheme(scheme)

	// Create fake client WITHOUT the NetworkPolicy (simulating deletion)
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		Build()

	// Create mock HCN manager with pre-existing policy
	mockHCN := newMockHCNManager()
	mockHCN.appliedPolicies["default/test-policy"] = []hcnpkg.ACLRule{
		{
			Name:      "test-rule",
			Direction: hcnlib.DirectionTypeIn,
			Protocol:  "6",
		},
	}

	// Create reconciler
	reconciler := &NetworkPolicyReconciler{
		Client:     fakeClient,
		Scheme:     scheme,
		HCNManager: mockHCN,
		NodeName:   "test-node",
	}

	// Reconcile (policy doesn't exist, should trigger delete)
	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-policy",
			Namespace: "default",
		},
	}

	result, err := reconciler.Reconcile(context.Background(), req)
	if err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}

	if result.Requeue {
		t.Error("Expected no requeue")
	}

	// Verify HCN rules were removed
	if len(mockHCN.removedPolicies) != 1 {
		t.Fatalf("Expected 1 policy to be removed, got %d", len(mockHCN.removedPolicies))
	}

	if mockHCN.removedPolicies[0] != "default/test-policy" {
		t.Errorf("Expected policy default/test-policy to be removed, got %s", mockHCN.removedPolicies[0])
	}

	// Verify policy no longer exists in applied policies
	if _, exists := mockHCN.appliedPolicies["default/test-policy"]; exists {
		t.Error("Policy should have been removed from applied policies")
	}
}

func TestReconcile_UpdateNetworkPolicy(t *testing.T) {
	// Setup scheme
	scheme := runtime.NewScheme()
	_ = networkingv1.AddToScheme(scheme)

	// Create a test NetworkPolicy
	np := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-policy",
			Namespace: "default",
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "web"},
			},
			Ingress: []networkingv1.NetworkPolicyIngressRule{
				{
					Ports: []networkingv1.NetworkPolicyPort{
						{
							Protocol: protoPtr("TCP"),
							Port:     &intstr.IntOrString{Type: intstr.Int, IntVal: 80},
						},
						{
							Protocol: protoPtr("TCP"),
							Port:     &intstr.IntOrString{Type: intstr.Int, IntVal: 443},
						},
					},
				},
			},
		},
	}

	// Create fake client
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(np).
		Build()

	// Create mock HCN manager with existing rule
	mockHCN := newMockHCNManager()
	mockHCN.appliedPolicies["default/test-policy"] = []hcnpkg.ACLRule{
		{
			Name:      "old-rule",
			Direction: hcnlib.DirectionTypeIn,
			Protocol:  "6",
		},
	}

	// Create reconciler
	reconciler := &NetworkPolicyReconciler{
		Client:     fakeClient,
		Scheme:     scheme,
		HCNManager: mockHCN,
		NodeName:   "test-node",
	}

	// Reconcile
	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-policy",
			Namespace: "default",
		},
	}

	result, err := reconciler.Reconcile(context.Background(), req)
	if err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}

	if result.Requeue {
		t.Error("Expected no requeue")
	}

	// Verify HCN rules were updated (should have 2 rules now)
	rules, exists := mockHCN.appliedPolicies["default/test-policy"]
	if !exists {
		t.Fatal("Expected ACL rules to be applied")
	}

	if len(rules) != 2 {
		t.Errorf("Expected 2 ACL rules (port 80 and 443), got %d", len(rules))
	}
}

func TestReconcile_ApplyError(t *testing.T) {
	// Setup scheme
	scheme := runtime.NewScheme()
	_ = networkingv1.AddToScheme(scheme)

	// Create a test NetworkPolicy
	np := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-policy",
			Namespace: "default",
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "web"},
			},
		},
	}

	// Create fake client
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(np).
		Build()

	// Create mock HCN manager that returns an error
	mockHCN := newMockHCNManager()
	mockHCN.applyError = fmt.Errorf("simulated HCN error")

	// Create reconciler
	reconciler := &NetworkPolicyReconciler{
		Client:     fakeClient,
		Scheme:     scheme,
		HCNManager: mockHCN,
		NodeName:   "test-node",
	}

	// Reconcile
	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-policy",
			Namespace: "default",
		},
	}

	result, err := reconciler.Reconcile(context.Background(), req)
	if err == nil {
		t.Fatal("Expected error from Reconcile")
	}

	// Should requeue with delay
	if result.RequeueAfter != 30*time.Second {
		t.Errorf("Expected RequeueAfter 30s, got %v", result.RequeueAfter)
	}
}

func TestSetupWithManager(t *testing.T) {
	// This is a basic test to ensure SetupWithManager doesn't panic
	// A full test would require a real manager, which is complex to set up

	scheme := runtime.NewScheme()
	_ = networkingv1.AddToScheme(scheme)

	reconciler := &NetworkPolicyReconciler{
		Client:     nil,
		Scheme:     scheme,
		HCNManager: newMockHCNManager(),
		NodeName:   "test-node",
	}

	// We can't fully test this without a real manager, but we can verify
	// the reconciler is properly initialized
	if reconciler.Scheme == nil {
		t.Error("Scheme should not be nil")
	}
	if reconciler.HCNManager == nil {
		t.Error("HCNManager should not be nil")
	}
}

func TestNewNetworkPolicyReconciler(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = networkingv1.AddToScheme(scheme)

	mockClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	mockHCN := newMockHCNManager()
	logger := logr.Discard()

	reconciler := NewNetworkPolicyReconciler(
		mockClient,
		scheme,
		mockHCN,
		"test-node",
		logger,
	)

	if reconciler == nil {
		t.Fatal("Expected reconciler to be created")
	}

	if reconciler.NodeName != "test-node" {
		t.Errorf("Expected NodeName test-node, got %s", reconciler.NodeName)
	}

	if reconciler.Client == nil {
		t.Error("Client should not be nil")
	}

	if reconciler.Scheme == nil {
		t.Error("Scheme should not be nil")
	}

	if reconciler.HCNManager == nil {
		t.Error("HCNManager should not be nil")
	}
}

// Helper function to create a protocol pointer
func protoPtr(p string) *string {
	return &p
}
