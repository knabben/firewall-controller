// +build windows

package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/Microsoft/hcsshim/hcn"
	"github.com/go-logr/logr"
	"github.com/go-logr/zapr"
	hcnpkg "github.com/knabben/firewall-controller/internal/hcn"
	"go.uber.org/zap"
)

func main() {
	var (
		action     = flag.String("action", "apply", "Action to perform: apply or remove")
		policyKey  = flag.String("policy", "test/example-policy", "Policy key (namespace/name)")
		verbose    = flag.Bool("verbose", false, "Enable verbose logging")
	)
	flag.Parse()

	// Setup logger
	var logger logr.Logger
	if *verbose {
		zapLog, _ := zap.NewDevelopment()
		logger = zapr.NewLogger(zapLog)
	} else {
		zapLog, _ := zap.NewProduction()
		logger = zapr.NewLogger(zapLog)
	}

	// Create HCN client and manager
	hcnClient := hcnpkg.NewHCNClient()
	manager := hcnpkg.NewManager(hcnClient, logger)

	switch *action {
	case "apply":
		if err := applyExampleRules(manager, *policyKey); err != nil {
			logger.Error(err, "Failed to apply ACL rules")
			os.Exit(1)
		}
		fmt.Println("Successfully applied ACL rules")

	case "remove":
		if err := manager.RemoveACLRules(*policyKey); err != nil {
			logger.Error(err, "Failed to remove ACL rules")
			os.Exit(1)
		}
		fmt.Println("Successfully removed ACL rules")

	case "list":
		listTrackedPolicies(manager)

	case "list-endpoints":
		listEndpoints(hcnClient, logger)

	default:
		fmt.Fprintf(os.Stderr, "Unknown action: %s\n", *action)
		flag.Usage()
		os.Exit(1)
	}
}

func applyExampleRules(manager *hcnpkg.Manager, policyKey string) error {
	// Example NetworkPolicy: Allow HTTP/HTTPS ingress and DNS egress
	rules := []hcnpkg.ACLRule{
		{
			Name:            "allow-http-ingress",
			Action:          hcn.ActionTypeAllow,
			Direction:       hcn.DirectionTypeIn,
			Protocol:        "6", // TCP
			LocalPorts:      "80",
			RemoteAddresses: "0.0.0.0/0",
			Priority:        100,
		},
		{
			Name:            "allow-https-ingress",
			Action:          hcn.ActionTypeAllow,
			Direction:       hcn.DirectionTypeIn,
			Protocol:        "6", // TCP
			LocalPorts:      "443",
			RemoteAddresses: "0.0.0.0/0",
			Priority:        101,
		},
		{
			Name:            "allow-dns-egress",
			Action:          hcn.ActionTypeAllow,
			Direction:       hcn.DirectionTypeOut,
			Protocol:        "17", // UDP
			RemotePorts:     "53",
			RemoteAddresses: "0.0.0.0/0",
			Priority:        102,
		},
		{
			Name:            "allow-https-egress",
			Action:          hcn.ActionTypeAllow,
			Direction:       hcn.DirectionTypeOut,
			Protocol:        "6", // TCP
			RemotePorts:     "443",
			RemoteAddresses: "0.0.0.0/0",
			Priority:        103,
		},
	}

	return manager.ApplyACLRules(policyKey, rules)
}

func listTrackedPolicies(manager *hcnpkg.Manager) {
	policies := manager.ListTrackedPolicies()
	if len(policies) == 0 {
		fmt.Println("No tracked policies found")
		return
	}

	fmt.Printf("Tracked policies (%d):\n", len(policies))
	for _, key := range policies {
		ruleSets, _ := manager.GetAppliedPolicies(key)
		fmt.Printf("  - %s (%d endpoints)\n", key, len(ruleSets))
		for _, rs := range ruleSets {
			fmt.Printf("      Endpoint: %s (%d policies)\n", rs.EndpointID, len(rs.Policies))
		}
	}
}

func listEndpoints(client hcnpkg.HCNClient, logger logr.Logger) {
	endpoints, err := client.ListEndpoints()
	if err != nil {
		logger.Error(err, "Failed to list endpoints")
		os.Exit(1)
	}

	if len(endpoints) == 0 {
		fmt.Println("No HCN endpoints found")
		return
	}

	fmt.Printf("HCN Endpoints (%d):\n", len(endpoints))
	for _, ep := range endpoints {
		fmt.Printf("  - ID: %s\n", ep.Id)
		fmt.Printf("    Name: %s\n", ep.Name)
		fmt.Printf("    IPAddress: %s\n", ep.IpConfigurations[0].IpAddress)
		fmt.Printf("    Policies: %d\n", len(ep.Policies))
		fmt.Println()
	}
}
