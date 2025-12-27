# HCN ACL Manual Testing Example

This example demonstrates how to manually apply and remove HCN ACL rules on a Windows node.

## Prerequisites

- Windows Server 2019 or later with HCN support
- Go 1.21 or later
- Administrator privileges (required for HCN operations)

## Building

On your Windows node:

```powershell
# Build the example binary
go build -o apply-acl.exe .
```

## Usage

### Apply Example ACL Rules

This will apply a set of example ACL rules (HTTP/HTTPS ingress, DNS/HTTPS egress) to all HCN endpoints:

```powershell
# Run as Administrator
.\apply-acl.exe -action apply -policy "test/example-policy"
```

### List HCN Endpoints

View all HCN endpoints on the system:

```powershell
.\apply-acl.exe -action list-endpoints
```

### List Tracked Policies

View which policies have been applied:

```powershell
.\apply-acl.exe -action list
```

### Remove ACL Rules

Remove previously applied rules:

```powershell
.\apply-acl.exe -action remove -policy "test/example-policy"
```

### Verbose Logging

Enable detailed logging:

```powershell
.\apply-acl.exe -action apply -policy "test/example-policy" -verbose
```

## Example Rules Applied

The example applies these ACL rules:

1. **Allow HTTP Ingress**: TCP port 80 from any source
2. **Allow HTTPS Ingress**: TCP port 443 from any source
3. **Allow DNS Egress**: UDP port 53 to any destination
4. **Allow HTTPS Egress**: TCP port 443 to any destination

## Verifying with PowerShell

You can verify the applied policies using native HCN PowerShell commands:

```powershell
# List all endpoints
Get-HnsEndpoint | Select Id, Name

# View policies on a specific endpoint
$ep = Get-HnsEndpoint -Id "<endpoint-id>"
$ep.Policies | ConvertFrom-Json | Format-List

# View ACL policies specifically
$ep.Policies | ConvertFrom-Json | Where-Object { $_.Type -eq "ACL" } | Format-List
```

## Testing Connectivity

After applying rules, test network connectivity:

```powershell
# From a pod on the Windows node, test allowed traffic
curl http://example.com  # Should work (HTTP allowed)
curl https://example.com # Should work (HTTPS allowed)
nslookup example.com     # Should work (DNS allowed)

# Test blocked traffic (if you add deny rules)
# ...
```

## Cleanup

To remove all test policies:

```powershell
.\apply-acl.exe -action remove -policy "test/example-policy"
```

## Troubleshooting

### "Access Denied" errors

Make sure you're running PowerShell as Administrator.

### "No HCN endpoints found"

Ensure you have containers or pods running on the Windows node. HCN endpoints are created when containers start.

```powershell
# Create a test container
docker run -d mcr.microsoft.com/windows/nanoserver:ltsc2022 ping -t localhost
```

### View HCN Networks

```powershell
Get-HnsNetwork | Select Name, Type, Id
```

## Integration with Kubernetes

This example shows the low-level HCN operations. In the full NetworkPolicy agent:

1. The controller watches NetworkPolicy resources
2. Converts them to ACLRule format
3. Uses this HCN manager to apply rules
4. Tracks applied rules for cleanup on policy deletion
