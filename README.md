# NetworkPolicy Agent for Windows

A Kubernetes agent that watches native NetworkPolicy resources and translates them into Windows Host Compute Network (HCN) ACL rules. This enables NetworkPolicy support on Windows nodes without requiring a CNI plugin that supports NetworkPolicy.

## Overview

The NetworkPolicy Agent runs as a DaemonSet on Windows nodes and provides:

- **Native NetworkPolicy Support**: Watches standard Kubernetes `networking.k8s.io/v1` NetworkPolicy resources (no custom CRDs)
- **HCN Integration**: Converts NetworkPolicy rules to Windows HCN ACL rules and applies them to container endpoints
- **Windows-Only**: Specifically designed for Windows Server 2019+ with HostProcess container support
- **Production-Ready**: Built with Kubebuilder, includes metrics, health probes, and proper RBAC

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    Kubernetes Cluster                           │
│                                                                 │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │         NetworkPolicy (native K8s resource)               │  │
│  │         networking.k8s.io/v1                               │  │
│  └───────────────────────────────────────────────────────────┘  │
│                              │                                   │
│                              ▼                                   │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │      NetworkPolicy Agent (DaemonSet on Windows)           │  │
│  │                                                            │  │
│  │  • Watches NetworkPolicy resources                         │  │
│  │  • Parses ingress/egress rules                            │  │
│  │  • Converts to HCN ACL policies                           │  │
│  │  • Applies via hcsshim                                    │  │
│  └───────────────────────────────────────────────────────────┘  │
│                              │                                   │
│                              ▼                                   │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │              Windows Host (HCN/HNS)                        │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

## Features

✅ **Native NetworkPolicy Support** - Works with standard Kubernetes NetworkPolicy resources
✅ **Ingress & Egress Rules** - Supports both traffic directions
✅ **IPBlock CIDR Filtering** - Filter traffic by source/destination IP ranges
✅ **Protocol Support** - TCP, UDP, and SCTP protocols
✅ **Port Filtering** - Allow/block specific ports
✅ **Automatic Rule Management** - Rules are automatically applied and cleaned up
✅ **HostProcess Container** - Runs with required privileges to access HCN APIs
✅ **Metrics & Health Probes** - Prometheus metrics and health/readiness endpoints
✅ **Leader Election** - Supports running multiple replicas (though DaemonSet typically runs one per node)

### Current Limitations

⚠️ **PodSelector** - Not yet supported (requires pod IP mapping)
⚠️ **NamespaceSelector** - Not yet supported (requires namespace resolution)
⚠️ **Named Ports** - Not yet supported (requires pod inspection)

Currently, only `ipBlock` peers are supported. Support for selectors is planned for future releases.

## Prerequisites

- **Kubernetes Cluster**: v1.28.0+
- **Windows Nodes**: Windows Server 2019+ with HCN support
- **HostProcess Support**: Kubernetes 1.22+ with HostProcess containers enabled
- **Go**: v1.23.0+ (for building from source)
- **Docker**: For building container images
- **kubectl**: v1.28.0+

## Installation

### Quick Start

1. **Build and push the Windows container image:**

```bash
export IMG=myregistry/networkpolicy-agent:v1.0.0
make docker-build-windows
make docker-push-windows
```

2. **Deploy to your cluster:**

```bash
# Update the image in config/manager/kustomization.yaml first
kubectl apply -k config/default
```

3. **Verify deployment:**

```bash
kubectl get daemonset -n networkpolicy-agent-system
kubectl get pods -n networkpolicy-agent-system -o wide
```

### Manual Deployment

If you prefer to deploy manifests directly:

```bash
# Deploy RBAC
kubectl apply -f config/rbac/

# Deploy the DaemonSet
kubectl apply -f config/manager/
```

## Usage

### Creating a NetworkPolicy

The agent watches standard Kubernetes NetworkPolicy resources:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-web-traffic
  namespace: default
spec:
  podSelector:
    matchLabels:
      app: web
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - ipBlock:
        cidr: 0.0.0.0/0
    ports:
    - protocol: TCP
      port: 80
    - protocol: TCP
      port: 443
  egress:
  - to:
    - ipBlock:
        cidr: 0.0.0.0/0
    ports:
    - protocol: TCP
      port: 443
    - protocol: UDP
      port: 53
```

### Viewing Applied Rules

On a Windows node, you can inspect HCN endpoints and their ACL policies:

```powershell
# List all HCN endpoints
Get-HnsEndpoint | Select Id, Name

# View policies on a specific endpoint
$ep = Get-HnsEndpoint -Id "<endpoint-id>"
$ep.Policies | ConvertFrom-Json | Where-Object { $_.Type -eq "ACL" } | Format-List
```

### Monitoring

The agent exposes Prometheus metrics on port 8443 (by default):

```bash
# Port-forward to access metrics
kubectl port-forward -n networkpolicy-agent-system deploy/controller-manager 8443:8443

# Access metrics
curl -k https://localhost:8443/metrics
```

Health and readiness probes are available at:
- Liveness: `http://localhost:8081/healthz`
- Readiness: `http://localhost:8081/readyz`

## Configuration

### Environment Variables

| Variable | Description | Required | Default |
|----------|-------------|----------|---------|
| `NODE_NAME` | Name of the Kubernetes node | Yes | Set via Downward API |

### Command-Line Flags

The agent supports standard controller-runtime flags:

- `--leader-elect`: Enable leader election (default: false)
- `--metrics-bind-address`: Metrics endpoint address (default: :8443)
- `--health-probe-bind-address`: Health probe address (default: :8081)

## Development

### Building from Source

```bash
# Build Windows binary (cross-compile from Linux/macOS)
GOOS=windows GOARCH=amd64 go build -o bin/networkpolicy-agent.exe ./cmd/main.go

# Or use Make
make build
```

### Running Tests

```bash
# Run all tests (requires Windows or will be skipped)
make test

# Run specific package tests
go test ./internal/converter/... -v
go test ./internal/hcn/... -v
go test ./internal/controller/... -v
```

### Manual Testing

A manual testing tool is included in `examples/apply-acl/`:

```bash
# Build the example (on Windows)
cd examples/apply-acl
go build -o apply-acl.exe .

# Apply example ACL rules
.\apply-acl.exe -action apply -policy "test/example"

# List tracked policies
.\apply-acl.exe -action list

# Remove rules
.\apply-acl.exe -action remove -policy "test/example"
```

See `examples/apply-acl/README.md` for more details.

## Project Structure

```
firewall-controller/
├── cmd/
│   └── main.go                    # Main entry point
├── internal/
│   ├── controller/                # NetworkPolicy reconciler
│   │   ├── networkpolicy_controller.go
│   │   └── networkpolicy_controller_test.go
│   ├── converter/                 # NetworkPolicy → ACL converter
│   │   ├── policy.go
│   │   └── policy_test.go
│   └── hcn/                       # HCN client wrapper
│       ├── types.go
│       ├── acl.go
│       └── acl_test.go
├── config/
│   ├── manager/                   # DaemonSet deployment
│   │   └── manager.yaml
│   ├── rbac/                      # RBAC configuration
│   │   └── role.yaml
│   └── default/                   # Kustomize overlays
│       └── kustomization.yaml
├── examples/
│   └── apply-acl/                 # Manual testing tool
├── Dockerfile                     # Linux Dockerfile (for development)
├── Dockerfile.windows             # Windows production Dockerfile
└── Makefile                       # Build automation
```

## Troubleshooting

### Agent Not Starting

**Check DaemonSet status:**
```bash
kubectl describe daemonset -n networkpolicy-agent-system controller-manager
```

**Check pod logs:**
```bash
kubectl logs -n networkpolicy-agent-system -l control-plane=controller-manager
```

**Common issues:**
- Pod not scheduled on Windows node: Check nodeSelector
- Permission errors: Verify RBAC and HostProcess configuration
- Image pull errors: Ensure image is accessible from Windows nodes

### Rules Not Applied

**Verify NetworkPolicy was created:**
```bash
kubectl get networkpolicy -A
kubectl describe networkpolicy <name> -n <namespace>
```

**Check agent logs for errors:**
```bash
kubectl logs -n networkpolicy-agent-system -l control-plane=controller-manager --tail=100
```

**Verify HCN endpoints exist:**
```powershell
# On Windows node
Get-HnsEndpoint
```

### No HCN Endpoints Found

This usually means no containers are running on the Windows node. The agent applies rules to existing HCN endpoints created by container runtime.

**Create a test pod:**
```bash
kubectl run test-pod --image=mcr.microsoft.com/windows/nanoserver:ltsc2022 --command -- ping -t localhost
```

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Guidelines

- Add tests for new features
- Update documentation
- Follow existing code style
- Ensure Windows builds succeed

## License

Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

## Acknowledgments

- Built with [Kubebuilder](https://book.kubebuilder.io/)
- Uses [controller-runtime](https://github.com/kubernetes-sigs/controller-runtime)
- Windows HCN integration via [hcsshim](https://github.com/microsoft/hcsshim)

## Related Documentation

- [ARCHITECTURE.md](ARCHITECTURE.md) - Detailed architecture documentation
- [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md) - Implementation details and phases
- [CLAUDE.md](CLAUDE.md) - Kubernetes controller development guide
- [examples/apply-acl/README.md](examples/apply-acl/README.md) - Manual testing guide
