//go:build windows

package hcn

import (
	"encoding/json"
	"fmt"
	"sync"

	"github.com/Microsoft/hcsshim/hcn"
	"github.com/go-logr/logr"
)

// Manager handles ACL rule application and tracking for HCN endpoints
type Manager struct {
	client HCNClient
	logger logr.Logger

	// mu protects the appliedPolicies map
	mu sync.RWMutex

	// appliedPolicies tracks which policies have been applied to which endpoints
	// Map: policyKey (namespace/name) -> list of RuleSets
	appliedPolicies map[string][]RuleSet
}

// NewManager creates a new ACL manager
func NewManager(client HCNClient, logger logr.Logger) *Manager {
	return &Manager{
		client:          client,
		logger:          logger,
		appliedPolicies: make(map[string][]RuleSet),
	}
}

// ApplyACLRules applies the given ACL rules to all HCN endpoints
// policyKey is typically "namespace/name" for tracking purposes
func (m *Manager) ApplyACLRules(policyKey string, rules []ACLRule) error {
	m.logger.Info("Applying ACL rules", "policyKey", policyKey, "ruleCount", len(rules))

	// List all HCN endpoints
	endpoints, err := m.client.ListEndpoints()
	if err != nil {
		return fmt.Errorf("failed to list HCN endpoints: %w", err)
	}

	if len(endpoints) == 0 {
		m.logger.Info("No HCN endpoints found, skipping rule application")
		return nil
	}

	// Convert ACL rules to HCN endpoint policies
	policies, err := m.buildPolicies(rules)
	if err != nil {
		return fmt.Errorf("failed to build HCN policies: %w", err)
	}

	// Track successful applications
	var ruleSets []RuleSet
	var applyErrors []error

	// Apply policies to each endpoint
	for _, endpoint := range endpoints {
		m.logger.V(1).Info("Applying policies to endpoint",
			"endpointID", endpoint.Id,
			"endpointName", endpoint.Name)

		request := hcn.PolicyEndpointRequest{
			Policies: policies,
		}

		err := m.client.ApplyEndpointPolicy(&endpoint, hcn.RequestTypeAdd, request)
		if err != nil {
			m.logger.Error(err, "Failed to apply policy to endpoint",
				"endpointID", endpoint.Id,
				"endpointName", endpoint.Name)
			applyErrors = append(applyErrors, fmt.Errorf("endpoint %s: %w", endpoint.Id, err))
			continue
		}

		// Track the applied policies (we need to store them for removal)
		ruleSets = append(ruleSets, RuleSet{
			EndpointID: endpoint.Id,
			Policies:   policies,
		})
	}

	// Store the tracking information
	m.mu.Lock()
	m.appliedPolicies[policyKey] = ruleSets
	m.mu.Unlock()

	// If we had partial failures, return an error
	if len(applyErrors) > 0 {
		return fmt.Errorf("failed to apply policies to %d/%d endpoints: %v",
			len(applyErrors), len(endpoints), applyErrors)
	}

	m.logger.Info("Successfully applied ACL rules",
		"policyKey", policyKey,
		"endpointCount", len(ruleSets))

	return nil
}

// RemoveACLRules removes previously applied ACL rules for the given policy key
func (m *Manager) RemoveACLRules(policyKey string) error {
	m.logger.Info("Removing ACL rules", "policyKey", policyKey)

	// Get the tracked rule sets
	m.mu.Lock()
	ruleSets, exists := m.appliedPolicies[policyKey]
	if !exists {
		m.mu.Unlock()
		m.logger.Info("No tracked policies found for key, nothing to remove", "policyKey", policyKey)
		return nil
	}
	// Remove from tracking immediately
	delete(m.appliedPolicies, policyKey)
	m.mu.Unlock()

	var removeErrors []error

	// Remove policies from each endpoint
	for _, ruleSet := range ruleSets {
		endpoint, err := m.client.GetEndpointByID(ruleSet.EndpointID)
		if err != nil {
			m.logger.Error(err, "Failed to get endpoint for policy removal",
				"endpointID", ruleSet.EndpointID)
			removeErrors = append(removeErrors, fmt.Errorf("get endpoint %s: %w", ruleSet.EndpointID, err))
			continue
		}

		// Build removal request with the same policies that were applied
		request := hcn.PolicyEndpointRequest{
			Policies: ruleSet.Policies,
		}

		err = m.client.RemoveEndpointPolicy(endpoint, hcn.RequestTypeRemove, request)
		if err != nil {
			m.logger.Error(err, "Failed to remove policy from endpoint",
				"endpointID", ruleSet.EndpointID)
			removeErrors = append(removeErrors, fmt.Errorf("endpoint %s: %w", ruleSet.EndpointID, err))
			continue
		}

		m.logger.V(1).Info("Successfully removed policies from endpoint",
			"endpointID", ruleSet.EndpointID,
			"policyCount", len(ruleSet.Policies))
	}

	if len(removeErrors) > 0 {
		return fmt.Errorf("failed to remove policies from %d/%d endpoints: %v",
			len(removeErrors), len(ruleSets), removeErrors)
	}

	m.logger.Info("Successfully removed ACL rules", "policyKey", policyKey)
	return nil
}

// buildPolicies converts ACLRules to HCN EndpointPolicy objects
func (m *Manager) buildPolicies(rules []ACLRule) ([]hcn.EndpointPolicy, error) {
	policies := make([]hcn.EndpointPolicy, 0, len(rules))

	for i, rule := range rules {
		// Create ACL policy setting
		aclSetting := hcn.AclPolicySetting{
			Protocols:       rule.Protocol,
			Action:          rule.Action,
			Direction:       rule.Direction,
			LocalAddresses:  "",                    // Not used for basic rules
			RemoteAddresses: rule.RemoteAddresses,
			LocalPorts:      rule.LocalPorts,
			RemotePorts:     rule.RemotePorts,
			Priority:        rule.Priority,
		}

		// Marshal the settings to JSON
		settingsJSON, err := json.Marshal(aclSetting)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal ACL setting for rule %d: %w", i, err)
		}

		// Create the endpoint policy
		policy := hcn.EndpointPolicy{
			Type:     hcn.ACL,
			Settings: settingsJSON,
		}

		policies = append(policies, policy)
	}

	return policies, nil
}

// GetAppliedPolicies returns the currently tracked policies (for testing/debugging)
func (m *Manager) GetAppliedPolicies(policyKey string) ([]RuleSet, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	ruleSets, exists := m.appliedPolicies[policyKey]
	return ruleSets, exists
}

// ListTrackedPolicies returns all tracked policy keys
func (m *Manager) ListTrackedPolicies() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	keys := make([]string, 0, len(m.appliedPolicies))
	for key := range m.appliedPolicies {
		keys = append(keys, key)
	}
	return keys
}
