//go:build windows

package hcn

import (
	"errors"
	"testing"

	"github.com/Microsoft/hcsshim/hcn"
	"github.com/go-logr/logr"
)

// mockHCNClient is a mock implementation of HCNClient for testing
type mockHCNClient struct {
	endpoints          []hcn.HostComputeEndpoint
	listEndpointsErr   error
	getEndpointErr     error
	applyPolicyErr     error
	removePolicyErr    error
	appliedPolicies    map[string][]hcn.EndpointPolicy // endpoint ID -> policies
	removedPolicies    map[string][]hcn.EndpointPolicy // endpoint ID -> policies
}

func newMockHCNClient() *mockHCNClient {
	return &mockHCNClient{
		endpoints:       []hcn.HostComputeEndpoint{},
		appliedPolicies: make(map[string][]hcn.EndpointPolicy),
		removedPolicies: make(map[string][]hcn.EndpointPolicy),
	}
}

func (m *mockHCNClient) ListEndpoints() ([]hcn.HostComputeEndpoint, error) {
	if m.listEndpointsErr != nil {
		return nil, m.listEndpointsErr
	}
	return m.endpoints, nil
}

func (m *mockHCNClient) GetEndpointByID(id string) (*hcn.HostComputeEndpoint, error) {
	if m.getEndpointErr != nil {
		return nil, m.getEndpointErr
	}
	for _, ep := range m.endpoints {
		if ep.Id == id {
			return &ep, nil
		}
	}
	return nil, errors.New("endpoint not found")
}

func (m *mockHCNClient) ApplyEndpointPolicy(endpoint *hcn.HostComputeEndpoint, requestType hcn.RequestType, request hcn.PolicyEndpointRequest) error {
	if m.applyPolicyErr != nil {
		return m.applyPolicyErr
	}
	m.appliedPolicies[endpoint.Id] = append(m.appliedPolicies[endpoint.Id], request.Policies...)
	return nil
}

func (m *mockHCNClient) RemoveEndpointPolicy(endpoint *hcn.HostComputeEndpoint, requestType hcn.RequestType, request hcn.PolicyEndpointRequest) error {
	if m.removePolicyErr != nil {
		return m.removePolicyErr
	}
	m.removedPolicies[endpoint.Id] = append(m.removedPolicies[endpoint.Id], request.Policies...)
	return nil
}

func TestApplyACLRules_Success(t *testing.T) {
	mockClient := newMockHCNClient()
	mockClient.endpoints = []hcn.HostComputeEndpoint{
		{Id: "ep-1", Name: "endpoint-1"},
		{Id: "ep-2", Name: "endpoint-2"},
	}

	manager := NewManager(mockClient, logr.Discard())

	rules := []ACLRule{
		{
			Name:            "allow-http",
			Action:          hcn.ActionTypeAllow,
			Direction:       hcn.DirectionTypeIn,
			Protocol:        "6", // TCP
			LocalPorts:      "80",
			RemoteAddresses: "0.0.0.0/0",
			Priority:        100,
		},
		{
			Name:            "allow-https",
			Action:          hcn.ActionTypeAllow,
			Direction:       hcn.DirectionTypeIn,
			Protocol:        "6", // TCP
			LocalPorts:      "443",
			RemoteAddresses: "0.0.0.0/0",
			Priority:        101,
		},
	}

	err := manager.ApplyACLRules("default/test-policy", rules)
	if err != nil {
		t.Fatalf("ApplyACLRules failed: %v", err)
	}

	// Verify policies were applied to all endpoints
	if len(mockClient.appliedPolicies) != 2 {
		t.Errorf("Expected policies applied to 2 endpoints, got %d", len(mockClient.appliedPolicies))
	}

	// Verify each endpoint received 2 policies
	for epID, policies := range mockClient.appliedPolicies {
		if len(policies) != 2 {
			t.Errorf("Expected 2 policies for endpoint %s, got %d", epID, len(policies))
		}
	}

	// Verify tracking
	ruleSets, exists := manager.GetAppliedPolicies("default/test-policy")
	if !exists {
		t.Error("Expected policy to be tracked")
	}
	if len(ruleSets) != 2 {
		t.Errorf("Expected 2 rule sets tracked, got %d", len(ruleSets))
	}
}

func TestApplyACLRules_NoEndpoints(t *testing.T) {
	mockClient := newMockHCNClient()
	mockClient.endpoints = []hcn.HostComputeEndpoint{} // No endpoints

	manager := NewManager(mockClient, logr.Discard())

	rules := []ACLRule{
		{
			Name:            "allow-http",
			Action:          hcn.ActionTypeAllow,
			Direction:       hcn.DirectionTypeIn,
			Protocol:        "6",
			LocalPorts:      "80",
			RemoteAddresses: "0.0.0.0/0",
			Priority:        100,
		},
	}

	err := manager.ApplyACLRules("default/test-policy", rules)
	if err != nil {
		t.Fatalf("ApplyACLRules should succeed with no endpoints: %v", err)
	}

	// Verify no policies were tracked
	ruleSets, exists := manager.GetAppliedPolicies("default/test-policy")
	if !exists || len(ruleSets) != 0 {
		t.Error("Expected empty rule sets when no endpoints exist")
	}
}

func TestApplyACLRules_ListEndpointsError(t *testing.T) {
	mockClient := newMockHCNClient()
	mockClient.listEndpointsErr = errors.New("failed to list endpoints")

	manager := NewManager(mockClient, logr.Discard())

	rules := []ACLRule{
		{
			Name:      "allow-http",
			Action:    hcn.ActionTypeAllow,
			Direction: hcn.DirectionTypeIn,
			Protocol:  "6",
			Priority:  100,
		},
	}

	err := manager.ApplyACLRules("default/test-policy", rules)
	if err == nil {
		t.Fatal("Expected error when ListEndpoints fails")
	}
}

func TestApplyACLRules_PartialFailure(t *testing.T) {
	mockClient := newMockHCNClient()
	mockClient.endpoints = []hcn.HostComputeEndpoint{
		{Id: "ep-1", Name: "endpoint-1"},
		{Id: "ep-2", Name: "endpoint-2"},
	}
	// Simulate failure on apply
	mockClient.applyPolicyErr = errors.New("failed to apply policy")

	manager := NewManager(mockClient, logr.Discard())

	rules := []ACLRule{
		{
			Name:      "allow-http",
			Action:    hcn.ActionTypeAllow,
			Direction: hcn.DirectionTypeIn,
			Protocol:  "6",
			Priority:  100,
		},
	}

	err := manager.ApplyACLRules("default/test-policy", rules)
	if err == nil {
		t.Fatal("Expected error when ApplyEndpointPolicy fails")
	}
}

func TestRemoveACLRules_Success(t *testing.T) {
	mockClient := newMockHCNClient()
	mockClient.endpoints = []hcn.HostComputeEndpoint{
		{Id: "ep-1", Name: "endpoint-1"},
		{Id: "ep-2", Name: "endpoint-2"},
	}

	manager := NewManager(mockClient, logr.Discard())

	// First apply some rules
	rules := []ACLRule{
		{
			Name:            "allow-http",
			Action:          hcn.ActionTypeAllow,
			Direction:       hcn.DirectionTypeIn,
			Protocol:        "6",
			LocalPorts:      "80",
			RemoteAddresses: "0.0.0.0/0",
			Priority:        100,
		},
	}

	err := manager.ApplyACLRules("default/test-policy", rules)
	if err != nil {
		t.Fatalf("ApplyACLRules failed: %v", err)
	}

	// Now remove them
	err = manager.RemoveACLRules("default/test-policy")
	if err != nil {
		t.Fatalf("RemoveACLRules failed: %v", err)
	}

	// Verify policies were removed from all endpoints
	if len(mockClient.removedPolicies) != 2 {
		t.Errorf("Expected policies removed from 2 endpoints, got %d", len(mockClient.removedPolicies))
	}

	// Verify tracking was cleared
	_, exists := manager.GetAppliedPolicies("default/test-policy")
	if exists {
		t.Error("Expected policy tracking to be cleared")
	}
}

func TestRemoveACLRules_NonExistentPolicy(t *testing.T) {
	mockClient := newMockHCNClient()
	manager := NewManager(mockClient, logr.Discard())

	// Try to remove a policy that was never applied
	err := manager.RemoveACLRules("default/non-existent")
	if err != nil {
		t.Fatalf("RemoveACLRules should succeed for non-existent policy: %v", err)
	}
}

func TestRemoveACLRules_GetEndpointError(t *testing.T) {
	mockClient := newMockHCNClient()
	mockClient.endpoints = []hcn.HostComputeEndpoint{
		{Id: "ep-1", Name: "endpoint-1"},
	}

	manager := NewManager(mockClient, logr.Discard())

	// Apply rules
	rules := []ACLRule{
		{
			Name:      "allow-http",
			Action:    hcn.ActionTypeAllow,
			Direction: hcn.DirectionTypeIn,
			Protocol:  "6",
			Priority:  100,
		},
	}

	err := manager.ApplyACLRules("default/test-policy", rules)
	if err != nil {
		t.Fatalf("ApplyACLRules failed: %v", err)
	}

	// Simulate error on GetEndpoint
	mockClient.getEndpointErr = errors.New("endpoint not found")

	err = manager.RemoveACLRules("default/test-policy")
	if err == nil {
		t.Fatal("Expected error when GetEndpoint fails")
	}
}

func TestBuildPolicies(t *testing.T) {
	mockClient := newMockHCNClient()
	manager := NewManager(mockClient, logr.Discard())

	rules := []ACLRule{
		{
			Name:            "allow-http",
			Action:          hcn.ActionTypeAllow,
			Direction:       hcn.DirectionTypeIn,
			Protocol:        "6",
			LocalPorts:      "80",
			RemoteAddresses: "0.0.0.0/0",
			Priority:        100,
		},
		{
			Name:           "allow-dns",
			Action:         hcn.ActionTypeAllow,
			Direction:      hcn.DirectionTypeOut,
			Protocol:       "17", // UDP
			RemotePorts:    "53",
			RemoteAddresses: "0.0.0.0/0",
			Priority:       101,
		},
	}

	policies, err := manager.buildPolicies(rules)
	if err != nil {
		t.Fatalf("buildPolicies failed: %v", err)
	}

	if len(policies) != 2 {
		t.Errorf("Expected 2 policies, got %d", len(policies))
	}

	for _, policy := range policies {
		if policy.Type != hcn.ACL {
			t.Errorf("Expected policy type ACL, got %v", policy.Type)
		}
		if len(policy.Settings) == 0 {
			t.Error("Expected policy settings to be populated")
		}
	}
}

func TestListTrackedPolicies(t *testing.T) {
	mockClient := newMockHCNClient()
	mockClient.endpoints = []hcn.HostComputeEndpoint{
		{Id: "ep-1", Name: "endpoint-1"},
	}

	manager := NewManager(mockClient, logr.Discard())

	rules := []ACLRule{
		{
			Name:      "allow-http",
			Action:    hcn.ActionTypeAllow,
			Direction: hcn.DirectionTypeIn,
			Protocol:  "6",
			Priority:  100,
		},
	}

	// Apply multiple policies
	_ = manager.ApplyACLRules("default/policy-1", rules)
	_ = manager.ApplyACLRules("default/policy-2", rules)
	_ = manager.ApplyACLRules("kube-system/policy-3", rules)

	trackedPolicies := manager.ListTrackedPolicies()
	if len(trackedPolicies) != 3 {
		t.Errorf("Expected 3 tracked policies, got %d", len(trackedPolicies))
	}

	// Verify all expected keys are present
	expectedKeys := map[string]bool{
		"default/policy-1":     true,
		"default/policy-2":     true,
		"kube-system/policy-3": true,
	}

	for _, key := range trackedPolicies {
		if !expectedKeys[key] {
			t.Errorf("Unexpected tracked policy key: %s", key)
		}
	}
}
