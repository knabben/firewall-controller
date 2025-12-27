//go:build windows

package converter

import (
	"testing"

	hcnlib "github.com/Microsoft/hcsshim/hcn"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func TestProtocolToNumber(t *testing.T) {
	tests := []struct {
		name     string
		protocol *corev1.Protocol
		expected string
	}{
		{
			name:     "TCP protocol",
			protocol: protoPtr(corev1.ProtocolTCP),
			expected: "6",
		},
		{
			name:     "UDP protocol",
			protocol: protoPtr(corev1.ProtocolUDP),
			expected: "17",
		},
		{
			name:     "SCTP protocol",
			protocol: protoPtr(corev1.ProtocolSCTP),
			expected: "132",
		},
		{
			name:     "nil protocol (default to TCP)",
			protocol: nil,
			expected: "6",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := protocolToNumber(tt.protocol)
			if result != tt.expected {
				t.Errorf("protocolToNumber() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestPortToString(t *testing.T) {
	tests := []struct {
		name     string
		port     *intstr.IntOrString
		expected string
	}{
		{
			name:     "integer port",
			port:     &intstr.IntOrString{Type: intstr.Int, IntVal: 80},
			expected: "80",
		},
		{
			name:     "named port (not supported, returns empty)",
			port:     &intstr.IntOrString{Type: intstr.String, StrVal: "http"},
			expected: "",
		},
		{
			name:     "nil port (match all ports)",
			port:     nil,
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := portToString(tt.port)
			if result != tt.expected {
				t.Errorf("portToString() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestGetPeerAddress(t *testing.T) {
	tests := []struct {
		name     string
		peer     networkingv1.NetworkPolicyPeer
		expected string
	}{
		{
			name: "IPBlock with CIDR",
			peer: networkingv1.NetworkPolicyPeer{
				IPBlock: &networkingv1.IPBlock{
					CIDR: "192.168.1.0/24",
				},
			},
			expected: "192.168.1.0/24",
		},
		{
			name: "PodSelector (not supported yet)",
			peer: networkingv1.NetworkPolicyPeer{
				PodSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"app": "web"},
				},
			},
			expected: "",
		},
		{
			name: "NamespaceSelector (not supported yet)",
			peer: networkingv1.NetworkPolicyPeer{
				NamespaceSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"env": "prod"},
				},
			},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getPeerAddress(tt.peer)
			if result != tt.expected {
				t.Errorf("getPeerAddress() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestNetworkPolicyToACLRules_IngressOnly(t *testing.T) {
	np := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "allow-http",
			Namespace: "default",
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "web"},
			},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			Ingress: []networkingv1.NetworkPolicyIngressRule{
				{
					Ports: []networkingv1.NetworkPolicyPort{
						{
							Protocol: protoPtr(corev1.ProtocolTCP),
							Port:     &intstr.IntOrString{Type: intstr.Int, IntVal: 80},
						},
					},
					From: []networkingv1.NetworkPolicyPeer{
						{
							IPBlock: &networkingv1.IPBlock{
								CIDR: "0.0.0.0/0",
							},
						},
					},
				},
			},
		},
	}

	rules := NetworkPolicyToACLRules(np)

	if len(rules) != 1 {
		t.Fatalf("Expected 1 rule, got %d", len(rules))
	}

	rule := rules[0]
	if rule.Direction != hcnlib.DirectionTypeIn {
		t.Errorf("Expected Direction In, got %v", rule.Direction)
	}
	if rule.Action != hcnlib.ActionTypeAllow {
		t.Errorf("Expected Action Allow, got %v", rule.Action)
	}
	if rule.Protocol != "6" {
		t.Errorf("Expected Protocol 6 (TCP), got %s", rule.Protocol)
	}
	if rule.LocalPorts != "80" {
		t.Errorf("Expected LocalPorts 80, got %s", rule.LocalPorts)
	}
	if rule.RemoteAddresses != "0.0.0.0/0" {
		t.Errorf("Expected RemoteAddresses 0.0.0.0/0, got %s", rule.RemoteAddresses)
	}
	if rule.Priority != 100 {
		t.Errorf("Expected Priority 100, got %d", rule.Priority)
	}
}

func TestNetworkPolicyToACLRules_EgressOnly(t *testing.T) {
	np := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "allow-dns",
			Namespace: "default",
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "web"},
			},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
			Egress: []networkingv1.NetworkPolicyEgressRule{
				{
					Ports: []networkingv1.NetworkPolicyPort{
						{
							Protocol: protoPtr(corev1.ProtocolUDP),
							Port:     &intstr.IntOrString{Type: intstr.Int, IntVal: 53},
						},
					},
					To: []networkingv1.NetworkPolicyPeer{
						{
							IPBlock: &networkingv1.IPBlock{
								CIDR: "8.8.8.8/32",
							},
						},
					},
				},
			},
		},
	}

	rules := NetworkPolicyToACLRules(np)

	if len(rules) != 1 {
		t.Fatalf("Expected 1 rule, got %d", len(rules))
	}

	rule := rules[0]
	if rule.Direction != hcnlib.DirectionTypeOut {
		t.Errorf("Expected Direction Out, got %v", rule.Direction)
	}
	if rule.Action != hcnlib.ActionTypeAllow {
		t.Errorf("Expected Action Allow, got %v", rule.Action)
	}
	if rule.Protocol != "17" {
		t.Errorf("Expected Protocol 17 (UDP), got %s", rule.Protocol)
	}
	if rule.RemotePorts != "53" {
		t.Errorf("Expected RemotePorts 53, got %s", rule.RemotePorts)
	}
	if rule.RemoteAddresses != "8.8.8.8/32" {
		t.Errorf("Expected RemoteAddresses 8.8.8.8/32, got %s", rule.RemoteAddresses)
	}
}

func TestNetworkPolicyToACLRules_MultiplePortsAndPeers(t *testing.T) {
	np := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "allow-web",
			Namespace: "default",
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "web"},
			},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			Ingress: []networkingv1.NetworkPolicyIngressRule{
				{
					Ports: []networkingv1.NetworkPolicyPort{
						{
							Protocol: protoPtr(corev1.ProtocolTCP),
							Port:     &intstr.IntOrString{Type: intstr.Int, IntVal: 80},
						},
						{
							Protocol: protoPtr(corev1.ProtocolTCP),
							Port:     &intstr.IntOrString{Type: intstr.Int, IntVal: 443},
						},
					},
					From: []networkingv1.NetworkPolicyPeer{
						{
							IPBlock: &networkingv1.IPBlock{
								CIDR: "10.0.0.0/8",
							},
						},
						{
							IPBlock: &networkingv1.IPBlock{
								CIDR: "192.168.0.0/16",
							},
						},
					},
				},
			},
		},
	}

	rules := NetworkPolicyToACLRules(np)

	// Should create 2 ports × 2 peers = 4 rules
	if len(rules) != 4 {
		t.Fatalf("Expected 4 rules (2 ports × 2 peers), got %d", len(rules))
	}

	// Verify priorities are incremental
	for i, rule := range rules {
		expectedPriority := uint16(100 + i)
		if rule.Priority != expectedPriority {
			t.Errorf("Rule %d: expected priority %d, got %d", i, expectedPriority, rule.Priority)
		}
	}

	// Verify all rules are ingress
	for i, rule := range rules {
		if rule.Direction != hcnlib.DirectionTypeIn {
			t.Errorf("Rule %d: expected Direction In, got %v", i, rule.Direction)
		}
	}
}

func TestNetworkPolicyToACLRules_IngressAndEgress(t *testing.T) {
	np := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "allow-web-and-dns",
			Namespace: "default",
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "web"},
			},
			PolicyTypes: []networkingv1.PolicyType{
				networkingv1.PolicyTypeIngress,
				networkingv1.PolicyTypeEgress,
			},
			Ingress: []networkingv1.NetworkPolicyIngressRule{
				{
					Ports: []networkingv1.NetworkPolicyPort{
						{
							Protocol: protoPtr(corev1.ProtocolTCP),
							Port:     &intstr.IntOrString{Type: intstr.Int, IntVal: 80},
						},
					},
					From: []networkingv1.NetworkPolicyPeer{
						{
							IPBlock: &networkingv1.IPBlock{
								CIDR: "0.0.0.0/0",
							},
						},
					},
				},
			},
			Egress: []networkingv1.NetworkPolicyEgressRule{
				{
					Ports: []networkingv1.NetworkPolicyPort{
						{
							Protocol: protoPtr(corev1.ProtocolUDP),
							Port:     &intstr.IntOrString{Type: intstr.Int, IntVal: 53},
						},
					},
					To: []networkingv1.NetworkPolicyPeer{
						{
							IPBlock: &networkingv1.IPBlock{
								CIDR: "0.0.0.0/0",
							},
						},
					},
				},
			},
		},
	}

	rules := NetworkPolicyToACLRules(np)

	if len(rules) != 2 {
		t.Fatalf("Expected 2 rules (1 ingress + 1 egress), got %d", len(rules))
	}

	// First rule should be ingress
	if rules[0].Direction != hcnlib.DirectionTypeIn {
		t.Errorf("First rule should be ingress, got %v", rules[0].Direction)
	}

	// Second rule should be egress
	if rules[1].Direction != hcnlib.DirectionTypeOut {
		t.Errorf("Second rule should be egress, got %v", rules[1].Direction)
	}

	// Verify priorities
	if rules[0].Priority != 100 {
		t.Errorf("First rule priority should be 100, got %d", rules[0].Priority)
	}
	if rules[1].Priority != 101 {
		t.Errorf("Second rule priority should be 101, got %d", rules[1].Priority)
	}
}

func TestNetworkPolicyToACLRules_EmptyRules(t *testing.T) {
	np := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "empty-policy",
			Namespace: "default",
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "web"},
			},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			Ingress:     []networkingv1.NetworkPolicyIngressRule{},
		},
	}

	rules := NetworkPolicyToACLRules(np)

	if len(rules) != 0 {
		t.Fatalf("Expected 0 rules for empty policy, got %d", len(rules))
	}
}

func TestNetworkPolicyToACLRules_NoPortsSpecified(t *testing.T) {
	np := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "allow-all-ports",
			Namespace: "default",
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "web"},
			},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			Ingress: []networkingv1.NetworkPolicyIngressRule{
				{
					// No ports specified - allows all ports
					From: []networkingv1.NetworkPolicyPeer{
						{
							IPBlock: &networkingv1.IPBlock{
								CIDR: "10.0.0.0/8",
							},
						},
					},
				},
			},
		},
	}

	rules := NetworkPolicyToACLRules(np)

	if len(rules) != 1 {
		t.Fatalf("Expected 1 rule, got %d", len(rules))
	}

	rule := rules[0]
	if rule.LocalPorts != "" {
		t.Errorf("Expected empty LocalPorts (match all), got %s", rule.LocalPorts)
	}
	if rule.Protocol != "" {
		t.Errorf("Expected empty Protocol (match all), got %s", rule.Protocol)
	}
}

// Helper function to create a protocol pointer
func protoPtr(p corev1.Protocol) *corev1.Protocol {
	return &p
}
