//go:build windows

package hcn

import (
	"github.com/Microsoft/hcsshim/hcn"
)

// ACLRule represents a network ACL rule to be applied to HCN endpoints
type ACLRule struct {
	// Name is a descriptive name for the rule
	Name string

	// Action defines whether to Allow or Block traffic
	Action hcn.ActionType

	// Direction specifies if this is an Ingress (In) or Egress (Out) rule
	Direction hcn.DirectionType

	// Protocol is the IP protocol number as a string (e.g., "6" for TCP, "17" for UDP)
	Protocol string

	// LocalPorts specifies the local port(s) for this rule (comma-separated)
	LocalPorts string

	// RemotePorts specifies the remote port(s) for this rule (comma-separated)
	RemotePorts string

	// RemoteAddresses specifies the remote IP address(es) or CIDR blocks
	RemoteAddresses string

	// Priority determines the order of rule evaluation (lower = higher priority)
	Priority uint16
}

// RuleSet tracks HCN policies applied to a specific endpoint
type RuleSet struct {
	// EndpointID is the HCN endpoint identifier
	EndpointID string

	// Policies are the actual HCN policies that were applied (for removal)
	Policies []hcn.EndpointPolicy
}

// HCNClient interface abstracts HCN operations for testing
type HCNClient interface {
	// ListEndpoints returns all HCN endpoints
	ListEndpoints() ([]hcn.HostComputeEndpoint, error)

	// GetEndpointByID retrieves a specific endpoint by ID
	GetEndpointByID(id string) (*hcn.HostComputeEndpoint, error)

	// ApplyEndpointPolicy applies a policy to an endpoint
	ApplyEndpointPolicy(endpoint *hcn.HostComputeEndpoint, requestType hcn.RequestType, request hcn.PolicyEndpointRequest) error

	// RemoveEndpointPolicy removes a policy from an endpoint
	RemoveEndpointPolicy(endpoint *hcn.HostComputeEndpoint, requestType hcn.RequestType, request hcn.PolicyEndpointRequest) error
}

// realHCNClient is the production implementation using actual hcsshim calls
type realHCNClient struct{}

// NewHCNClient creates a new HCN client
func NewHCNClient() HCNClient {
	return &realHCNClient{}
}

// ListEndpoints implements HCNClient
func (c *realHCNClient) ListEndpoints() ([]hcn.HostComputeEndpoint, error) {
	return hcn.ListEndpoints()
}

// GetEndpointByID implements HCNClient
func (c *realHCNClient) GetEndpointByID(id string) (*hcn.HostComputeEndpoint, error) {
	return hcn.GetEndpointByID(id)
}

// ApplyEndpointPolicy implements HCNClient
func (c *realHCNClient) ApplyEndpointPolicy(endpoint *hcn.HostComputeEndpoint, requestType hcn.RequestType, request hcn.PolicyEndpointRequest) error {
	return endpoint.ApplyPolicy(requestType, request)
}

// RemoveEndpointPolicy implements HCNClient
func (c *realHCNClient) RemoveEndpointPolicy(endpoint *hcn.HostComputeEndpoint, requestType hcn.RequestType, request hcn.PolicyEndpointRequest) error {
	return endpoint.ApplyPolicy(requestType, request)
}
