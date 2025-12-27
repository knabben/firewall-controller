//go:build windows

package converter

import (
	"fmt"

	hcnlib "github.com/Microsoft/hcsshim/hcn"
	hcnpkg "github.com/knabben/firewall-controller/internal/hcn"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

// NetworkPolicyToACLRules converts a Kubernetes NetworkPolicy to HCN ACL rules
// It expands the ingress and egress rules into individual ACL rules with incremental priorities
func NetworkPolicyToACLRules(np *networkingv1.NetworkPolicy) []hcnpkg.ACLRule {
	var rules []hcnpkg.ACLRule
	priority := uint16(100) // Starting priority

	// Process ingress rules
	for _, ingressRule := range np.Spec.Ingress {
		ingressRules := convertIngressRule(np, ingressRule, &priority)
		rules = append(rules, ingressRules...)
	}

	// Process egress rules
	for _, egressRule := range np.Spec.Egress {
		egressRules := convertEgressRule(np, egressRule, &priority)
		rules = append(rules, egressRules...)
	}

	return rules
}

// convertIngressRule converts a single ingress rule to one or more ACL rules
func convertIngressRule(np *networkingv1.NetworkPolicy, ingressRule networkingv1.NetworkPolicyIngressRule, priority *uint16) []hcnpkg.ACLRule {
	var rules []hcnpkg.ACLRule

	// If no ports specified, create a rule for all ports
	if len(ingressRule.Ports) == 0 {
		// If no From specified, allow from anywhere
		if len(ingressRule.From) == 0 {
			rule := hcnpkg.ACLRule{
				Name:            fmt.Sprintf("%s/%s-ingress", np.Namespace, np.Name),
				Action:          hcnlib.ActionTypeAllow,
				Direction:       hcnlib.DirectionTypeIn,
				Protocol:        "", // Empty means all protocols
				RemoteAddresses: "0.0.0.0/0",
				Priority:        *priority,
			}
			*priority++
			rules = append(rules, rule)
		} else {
			// Create rule for each From peer
			for _, from := range ingressRule.From {
				remoteAddr := getPeerAddress(from)
				if remoteAddr == "" {
					continue // Skip if we can't determine address
				}

				rule := hcnpkg.ACLRule{
					Name:            fmt.Sprintf("%s/%s-ingress", np.Namespace, np.Name),
					Action:          hcnlib.ActionTypeAllow,
					Direction:       hcnlib.DirectionTypeIn,
					Protocol:        "",
					RemoteAddresses: remoteAddr,
					Priority:        *priority,
				}
				*priority++
				rules = append(rules, rule)
			}
		}
	} else {
		// Create rules for each port
		for _, port := range ingressRule.Ports {
			// If no From specified, allow from anywhere
			if len(ingressRule.From) == 0 {
				rule := hcnpkg.ACLRule{
					Name:            fmt.Sprintf("%s/%s-ingress", np.Namespace, np.Name),
					Action:          hcnlib.ActionTypeAllow,
					Direction:       hcnlib.DirectionTypeIn,
					Protocol:        protocolToNumber(port.Protocol),
					LocalPorts:      portToString(port.Port),
					RemoteAddresses: "0.0.0.0/0",
					Priority:        *priority,
				}
				*priority++
				rules = append(rules, rule)
			} else {
				// Create rule for each From peer × port combination
				for _, from := range ingressRule.From {
					remoteAddr := getPeerAddress(from)
					if remoteAddr == "" {
						continue // Skip if we can't determine address
					}

					rule := hcnpkg.ACLRule{
						Name:            fmt.Sprintf("%s/%s-ingress", np.Namespace, np.Name),
						Action:          hcnlib.ActionTypeAllow,
						Direction:       hcnlib.DirectionTypeIn,
						Protocol:        protocolToNumber(port.Protocol),
						LocalPorts:      portToString(port.Port),
						RemoteAddresses: remoteAddr,
						Priority:        *priority,
					}
					*priority++
					rules = append(rules, rule)
				}
			}
		}
	}

	return rules
}

// convertEgressRule converts a single egress rule to one or more ACL rules
func convertEgressRule(np *networkingv1.NetworkPolicy, egressRule networkingv1.NetworkPolicyEgressRule, priority *uint16) []hcnpkg.ACLRule {
	var rules []hcnpkg.ACLRule

	// If no ports specified, create a rule for all ports
	if len(egressRule.Ports) == 0 {
		// If no To specified, allow to anywhere
		if len(egressRule.To) == 0 {
			rule := hcnpkg.ACLRule{
				Name:            fmt.Sprintf("%s/%s-egress", np.Namespace, np.Name),
				Action:          hcnlib.ActionTypeAllow,
				Direction:       hcnlib.DirectionTypeOut,
				Protocol:        "", // Empty means all protocols
				RemoteAddresses: "0.0.0.0/0",
				Priority:        *priority,
			}
			*priority++
			rules = append(rules, rule)
		} else {
			// Create rule for each To peer
			for _, to := range egressRule.To {
				remoteAddr := getPeerAddress(to)
				if remoteAddr == "" {
					continue // Skip if we can't determine address
				}

				rule := hcnpkg.ACLRule{
					Name:            fmt.Sprintf("%s/%s-egress", np.Namespace, np.Name),
					Action:          hcnlib.ActionTypeAllow,
					Direction:       hcnlib.DirectionTypeOut,
					Protocol:        "",
					RemoteAddresses: remoteAddr,
					Priority:        *priority,
				}
				*priority++
				rules = append(rules, rule)
			}
		}
	} else {
		// Create rules for each port
		for _, port := range egressRule.Ports {
			// If no To specified, allow to anywhere
			if len(egressRule.To) == 0 {
				rule := hcnpkg.ACLRule{
					Name:            fmt.Sprintf("%s/%s-egress", np.Namespace, np.Name),
					Action:          hcnlib.ActionTypeAllow,
					Direction:       hcnlib.DirectionTypeOut,
					Protocol:        protocolToNumber(port.Protocol),
					RemotePorts:     portToString(port.Port),
					RemoteAddresses: "0.0.0.0/0",
					Priority:        *priority,
				}
				*priority++
				rules = append(rules, rule)
			} else {
				// Create rule for each To peer × port combination
				for _, to := range egressRule.To {
					remoteAddr := getPeerAddress(to)
					if remoteAddr == "" {
						continue // Skip if we can't determine address
					}

					rule := hcnpkg.ACLRule{
						Name:            fmt.Sprintf("%s/%s-egress", np.Namespace, np.Name),
						Action:          hcnlib.ActionTypeAllow,
						Direction:       hcnlib.DirectionTypeOut,
						Protocol:        protocolToNumber(port.Protocol),
						RemotePorts:     portToString(port.Port),
						RemoteAddresses: remoteAddr,
						Priority:        *priority,
					}
					*priority++
					rules = append(rules, rule)
				}
			}
		}
	}

	return rules
}

// getPeerAddress extracts the IP address/CIDR from a NetworkPolicyPeer
func getPeerAddress(peer networkingv1.NetworkPolicyPeer) string {
	// For now, only support IPBlock
	// TODO: Add support for PodSelector and NamespaceSelector (requires pod IP mapping)
	if peer.IPBlock != nil {
		return peer.IPBlock.CIDR
	}

	// If PodSelector or NamespaceSelector is specified, we need pod IP resolution
	// This is a future enhancement (Phase 9 in the implementation plan)
	return ""
}

// protocolToNumber converts a Kubernetes protocol to its IP protocol number
func protocolToNumber(proto *corev1.Protocol) string {
	if proto == nil {
		// Default to TCP if not specified
		return "6"
	}

	switch *proto {
	case corev1.ProtocolTCP:
		return "6"
	case corev1.ProtocolUDP:
		return "17"
	case corev1.ProtocolSCTP:
		return "132"
	default:
		// Default to TCP
		return "6"
	}
}

// portToString converts an IntOrString port to a string
func portToString(port *intstr.IntOrString) string {
	if port == nil {
		// If no port specified, match all ports (empty string)
		return ""
	}

	switch port.Type {
	case intstr.Int:
		return fmt.Sprintf("%d", port.IntVal)
	case intstr.String:
		// Named ports are not directly supported by HCN ACLs
		// In a real implementation, this would need to be resolved
		// to a port number via pod inspection
		// For now, return empty to match all ports
		return ""
	default:
		return ""
	}
}
