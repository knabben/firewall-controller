# NetworkPolicyAgent Implementation Plan

## Project Overview
Build a Windows-only Kubernetes agent that watches native NetworkPolicy resources and converts them into HCN (Host Compute Network) ACL rules using the hcsshim library. This is a simplified architecture compared to traditional NetworkPolicy controllers - it runs as a DaemonSet on Windows nodes only.

## Current State
- Repository initialized with Kubernetes project governance files
- ARCHITECTURE.md defines the target design
- No Go code exists yet (greenfield project)
- CLAUDE.md provides controller development guidelines

## Architecture (from ARCHITECTURE.md)

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

## Key Design Decisions (Aligned with ARCHITECTURE.md)

### 1. No Custom CRD
- Uses **native Kubernetes NetworkPolicy** (`networking.k8s.io/v1`)
- No need to define custom types or run `make generate/manifests`
- Simpler deployment, better ecosystem compatibility

### 2. Simplified Project Structure
```
firewall-controller/
├── cmd/
│   └── main.go                    # Entry point, manager setup
├── internal/
│   ├── controller/
│   │   └── networkpolicy_controller.go  # Reconciler logic
│   ├── hcn/
│   │   └── acl.go                 # hcsshim wrapper
│   └── converter/
│       └── policy.go              # NetworkPolicy → HCN ACL conversion
├── config/
│   ├── rbac/
│   │   └── role.yaml              # ClusterRole for NetworkPolicy/Pod
│   └── daemonset/
│       └── daemonset.yaml         # DaemonSet deployment
├── go.mod
├── go.sum
├── Makefile
├── Dockerfile.windows
├── ARCHITECTURE.md                # ✓ Already exists
└── CLAUDE.md                      # ✓ Already exists
```

### 3. Core Components

#### A. NetworkPolicy Reconciler
- **Purpose**: Main reconciliation loop
- **Watches**: `networking.k8s.io/v1/NetworkPolicy` (cluster-wide)
- **Responsibilities**:
  - Fetch NetworkPolicy on Add/Update/Delete events
  - Convert policy to HCN ACL rules via converter
  - Apply rules via HCN client
  - Track applied rules for cleanup
  - Handle deletion (remove HCN rules)

#### B. Converter (NetworkPolicy → HCN ACL)
- **Purpose**: Translation layer between K8s and Windows networking
- **Input**: `networkingv1.NetworkPolicy`
- **Output**: `[]ACLRule` (HCN-compatible)
- **Logic**:
  - **Ingress rules**: Direction=In, parse `from` → RemoteAddresses, `ports` → LocalPorts
  - **Egress rules**: Direction=Out, parse `to` → RemoteAddresses, `ports` → RemotePorts
  - **Protocol mapping**: TCP→6, UDP→17, ICMP→1
  - **Priority assignment**: Sequential (100, 101, 102...)

#### C. HCN Client Wrapper
- **Purpose**: Abstract hcsshim operations
- **Technology**: `github.com/microsoft/hcsshim/hcn` package
- **Operations**:
  - `ApplyACLRules(policyKey string, rules []ACLRule)`: Apply rules to all HCN endpoints
  - `RemoveACLRules(policyKey string)`: Remove rules for a specific policy
  - `buildPolicies(rules []ACLRule) []hcn.EndpointPolicy`: Convert to hcsshim format
- **State Tracking**: In-memory map `policyKey → []endpointIDs`

### 4. NetworkPolicy → HCN ACL Conversion Strategy

#### Conversion Algorithm (from ARCHITECTURE.md)

```
For each NetworkPolicy NP:
  priority := 100

  For each ingressRule in NP.Spec.Ingress:
    For each port in ingressRule.Ports:
      For each from in ingressRule.From:
        Create ACLRule:
          - Direction: In
          - Action: Allow
          - Protocol: port.Protocol → number
          - LocalPorts: port.Port
          - RemoteAddresses: from.IPBlock.CIDR (if IPBlock)
          - Priority: priority++

  For each egressRule in NP.Spec.Egress:
    For each port in egressRule.Ports:
      For each to in egressRule.To:
        Create ACLRule:
          - Direction: Out
          - Action: Allow
          - Protocol: port.Protocol → number
          - RemotePorts: port.Port
          - RemoteAddresses: to.IPBlock.CIDR (if IPBlock)
          - Priority: priority++
```

#### Example Conversion

**Input (NetworkPolicy)**:
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-web
  namespace: default
spec:
  podSelector:
    matchLabels:
      app: webserver
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
    - protocol: UDP
      port: 53
```

**Output (HCN ACL Rules)**:
```go
[]ACLRule{
  {
    Name: "allow-web-ingress",
    Action: hcn.ActionTypeAllow,
    Direction: hcn.DirectionTypeIn,
    Protocol: "6",  // TCP
    LocalPorts: "80",
    RemoteAddresses: "0.0.0.0/0",
    Priority: 100,
  },
  {
    Name: "allow-web-ingress",
    Action: hcn.ActionTypeAllow,
    Direction: hcn.DirectionTypeIn,
    Protocol: "6",  // TCP
    LocalPorts: "443",
    RemoteAddresses: "0.0.0.0/0",
    Priority: 101,
  },
  {
    Name: "allow-web-egress",
    Action: hcn.ActionTypeAllow,
    Direction: hcn.DirectionTypeOut,
    Protocol: "17",  // UDP
    RemotePorts: "53",
    RemoteAddresses: "0.0.0.0/0",
    Priority: 102,
  },
}
```

### 5. Rule Tracking & Cleanup Strategy

#### In-Memory Tracking
```go
var (
    // Map: policyKey (namespace/name) → list of endpoint IDs
    appliedPolicies = make(map[string][]string)
    mu sync.Mutex
)
```

#### Apply Flow
```
1. Reconciler calls ApplyACLRules(policyKey, rules)
2. HCN client:
   a. ListEndpoints() to get all HCN endpoints
   b. For each endpoint:
      - Convert rules to hcn.EndpointPolicy
      - Call ep.ApplyPolicy(RequestTypeAdd, policies)
   c. Track: appliedPolicies[policyKey] = endpointIDs
```

#### Delete Flow
```
1. Reconciler detects NetworkPolicy deletion (NotFound)
2. Calls RemoveACLRules(policyKey)
3. HCN client:
   a. Lookup endpointIDs from appliedPolicies[policyKey]
   b. For each endpointID:
      - Remove specific ACL policies (need to track rule IDs)
   c. Delete appliedPolicies[policyKey]
```

#### Critical Gap in ARCHITECTURE.md
The current ARCHITECTURE.md shows simplified tracking but doesn't handle:
- **Rule ID tracking**: Need to store actual HCN policy IDs for precise removal
- **Persistence**: In-memory map lost on agent restart
- **Orphan cleanup**: Stale rules if agent crashes

**Enhanced Tracking (to implement)**:
```go
type RuleTracker struct {
    mu sync.RWMutex
    // Map: policyKey → list of RuleSets
    policies map[string][]RuleSet
}

type RuleSet struct {
    EndpointID string   // HCN endpoint ID
    RuleIDs    []string // HCN policy IDs (for removal)
}
```

### 6. Error Handling & Edge Cases

#### Scenario 1: HCN Endpoint Not Found
**Cause**: Pod exists but no HCN endpoint yet
**Solution**:
- Log warning, skip endpoint
- Return success (don't requeue entire policy)
- Rely on pod update events to retry

#### Scenario 2: NetworkPolicy Deletion
**Handling**:
- Reconcile returns `NotFound` error
- Call `reconcileDelete()` to remove HCN rules
- Return `ctrl.Result{}, nil` (success)

#### Scenario 3: Partial Apply Failure
**Cause**: 10 endpoints, 3 fail to apply
**Solution**:
- Track successful applies
- Return error → controller-runtime requeues with backoff
- On retry, check existing rules (idempotency)

#### Scenario 4: Agent Restart
**Problem**: In-memory tracking lost
**Solution**:
- On startup, list all HCN endpoints
- Query existing ACL policies
- Match with current NetworkPolicies in API server
- Remove orphans, re-apply missing rules

#### Scenario 5: podSelector with Label Matching
**Challenge**: NetworkPolicy targets specific pods, but we apply to all endpoints
**Solution** (future enhancement):
- Add pod watcher to track pod labels → IP mapping
- Filter endpoints by pod selector before applying rules
- **For MVP**: Apply to all endpoints (simpler, but less precise)

### 7. Dependencies

```go
module github.com/knabben/firewall-controller

go 1.21

require (
    k8s.io/api v0.28.0
    k8s.io/apimachinery v0.28.0
    k8s.io/client-go v0.28.0
    sigs.k8s.io/controller-runtime v0.16.0
    github.com/microsoft/hcsshim v0.12.0
    github.com/go-logr/logr v1.2.4
)
```

### 8. RBAC Requirements

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: networkpolicy-agent
rules:
- apiGroups: ["networking.k8s.io"]
  resources: ["networkpolicies"]
  verbs: ["get", "list", "watch"]
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list", "watch"]  # Future: for podSelector filtering
```

### 9. Deployment Model

**DaemonSet** (from ARCHITECTURE.md):
- **nodeSelector**: `kubernetes.io/os: windows`
- **hostNetwork**: `true` (access HCN directly)
- **securityContext**:
  - `windowsOptions.hostProcess: true`
  - `runAsUserName: "NT AUTHORITY\\SYSTEM"`
- **Environment**: `NODE_NAME` from downward API

### 10. Implementation Phases

#### Phase 1: Project Initialization
**Tasks**:
1. Initialize Go module: `go mod init github.com/knabben/firewall-controller`
2. Add dependencies (controller-runtime, hcsshim, k8s client-go)
3. Create directory structure: `cmd/`, `internal/controller/`, `internal/hcn/`, `internal/converter/`
4. Add Makefile with build/test targets
5. Create basic Dockerfile.windows

**Files Created**:
- `go.mod`, `go.sum`
- `Makefile`
- `Dockerfile.windows`

#### Phase 2: Converter Implementation
**Tasks**:
1. Implement `internal/converter/policy.go`:
   - `NetworkPolicyToACLRules(np *networkingv1.NetworkPolicy) []ACLRule`
   - Helper: `protocolToNumber(proto *corev1.Protocol) string`
   - Helper: `portToString(port *intstr.IntOrString) string`
2. Write unit tests:
   - Test ingress conversion
   - Test egress conversion
   - Test protocol mapping
   - Test multi-port, multi-peer expansion

**Key Logic**:
- Loop through `np.Spec.Ingress` and `np.Spec.Egress`
- For each rule, expand Ports × Peers into individual ACLRules
- Assign incremental priorities (100, 101, 102...)

#### Phase 3: HCN Client Wrapper
**Tasks**:
1. Implement `internal/hcn/acl.go`:
   - `ApplyACLRules(policyKey string, rules []ACLRule) error`
   - `RemoveACLRules(policyKey string) error`
   - `buildPolicies(rules []ACLRule) []hcn.EndpointPolicy`
   - Helpers: `listEndpoints()`, `applyToEndpoint()`
2. Add in-memory tracking: `appliedPolicies map[string][]string`
3. Write unit tests with mock HCN interface

**Critical Implementation Details**:
- Use `hcn.ListEndpoints()` to get all endpoints
- Convert ACLRule to `hcn.AclPolicySetting` (JSON marshal)
- Call `ep.ApplyPolicy(hcn.RequestTypeAdd, req)` for each endpoint
- Track endpoint IDs for later removal

#### Phase 4: Reconciler Implementation
**Tasks**:
1. Implement `internal/controller/networkpolicy_controller.go`:
   - `Reconcile(ctx, req) (ctrl.Result, error)`
   - `reconcileDelete(ctx, key) (ctrl.Result, error)`
   - `SetupWithManager(mgr) error`
2. Wire up converter and HCN client
3. Add structured logging
4. Write unit tests with fake Kubernetes client

**Reconciler Logic** (from ARCHITECTURE.md):
```go
func (r *NetworkPolicyReconciler) Reconcile(ctx, req) {
    // 1. Fetch NetworkPolicy
    var np networkingv1.NetworkPolicy
    if err := r.Get(ctx, req.NamespacedName, &np); err != nil {
        if NotFound(err) {
            return r.reconcileDelete(ctx, req.NamespacedName)
        }
        return err
    }

    // 2. Convert to HCN ACL rules
    rules := converter.NetworkPolicyToACLRules(&np)

    // 3. Apply via HCN
    if err := hcn.ApplyACLRules(req.String(), rules); err != nil {
        return RequeueAfter(30s)
    }

    return Success
}
```

#### Phase 5: Main Entry Point
**Tasks**:
1. Implement `cmd/main.go`:
   - Setup scheme with `networkingv1.AddToScheme()`
   - Create controller manager with `ctrl.NewManager()`
   - Register NetworkPolicyReconciler
   - Start manager with signal handler
2. Add environment variable handling (NODE_NAME)
3. Add health/readiness probes

**Main Function** (from ARCHITECTURE.md):
```go
func main() {
    nodeName := os.Getenv("NODE_NAME")

    mgr, _ := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
        Scheme: scheme,
    })

    _ = (&controller.NetworkPolicyReconciler{
        Client:   mgr.GetClient(),
        NodeName: nodeName,
    }).SetupWithManager(mgr)

    _ = mgr.Start(ctrl.SetupSignalHandler())
}
```

#### Phase 6: Kubernetes Manifests
**Tasks**:
1. Create `config/rbac/role.yaml`:
   - ClusterRole with NetworkPolicy watch permissions
   - ServiceAccount, ClusterRoleBinding
2. Create `config/daemonset/daemonset.yaml`:
   - DaemonSet with Windows nodeSelector
   - hostProcess security context
   - NODE_NAME environment variable
3. Test deployment on Windows cluster

#### Phase 7: Build & Container Image
**Tasks**:
1. Complete Makefile:
   - `make build`: Build Windows binary
   - `make test`: Run unit tests
   - `make docker-build`: Build Windows container
   - `make deploy`: Apply manifests
2. Create Dockerfile.windows:
   - Use Windows Server Core base image
   - Copy binary to container
   - Set entrypoint

#### Phase 8: Testing & Validation
**Tasks**:
1. Deploy to Windows test cluster
2. Create test NetworkPolicies:
   - Allow ingress on port 80
   - Allow egress DNS (UDP 53)
   - Block all other traffic
3. Verify HCN rules:
   - `Get-HnsEndpoint | Select Policies`
   - Inspect ACL rules on endpoints
4. Test connectivity:
   - Allowed traffic passes
   - Blocked traffic fails
5. Test deletion:
   - Delete NetworkPolicy
   - Verify HCN rules removed

#### Phase 9: Observability (Future)
**Tasks**:
1. Add Prometheus metrics:
   - `networkpolicies_watched`
   - `acl_rules_applied`
   - `reconciliation_errors`
2. Add structured logging with context
3. Add tracing (optional)

### 11. Critical Files to Create (In Order)

1. **go.mod** - Module definition
2. **Makefile** - Build automation
3. **internal/converter/policy.go** - Core conversion logic
4. **internal/converter/policy_test.go** - Converter tests
5. **internal/hcn/acl.go** - HCN client wrapper
6. **internal/hcn/acl_test.go** - HCN tests with mocks
7. **internal/controller/networkpolicy_controller.go** - Reconciler
8. **internal/controller/networkpolicy_controller_test.go** - Reconciler tests
9. **cmd/main.go** - Entry point
10. **config/rbac/role.yaml** - RBAC manifests
11. **config/daemonset/daemonset.yaml** - Deployment manifest
12. **Dockerfile.windows** - Container image

### 12. Testing Strategy

**Unit Tests**:
- Converter: Test ingress/egress → ACLRule conversion
- HCN Client: Mock hcsshim interface, verify ApplyPolicy calls
- Reconciler: Fake Kubernetes client, verify reconciliation flow

**Integration Tests**:
- Use controller-runtime's envtest
- Create NetworkPolicy, verify reconciler calls HCN client
- Delete NetworkPolicy, verify cleanup called

**Manual E2E Tests**:
- Deploy to Windows cluster
- Apply various NetworkPolicy configurations
- Verify with `Get-HnsEndpoint`
- Test network connectivity

### 13. Key Differences from Original Plan

The ARCHITECTURE.md simplifies the design significantly:

| Aspect | Original Plan | ARCHITECTURE.md | Decision |
|--------|--------------|-----------------|----------|
| **CRD** | Custom FirewallRule CRD | Native NetworkPolicy | ✓ Use native (simpler) |
| **Pod Tracking** | Separate pod watcher/indexer | Not mentioned | Defer to Phase 9 (MVP: apply to all endpoints) |
| **Persistence** | File-based tracker | In-memory map only | Add file persistence (important for restarts) |
| **Orphan Cleanup** | Periodic scan (5 min) | Not mentioned | Add periodic cleanup (important) |
| **podSelector Filtering** | Match pods by labels | Not mentioned | Defer to Phase 9 (MVP: all endpoints) |
| **Priority Strategy** | DENY=1000, ALLOW=500 | Sequential 100+ | ✓ Use sequential (simpler) |

### 14. Enhancements Beyond ARCHITECTURE.md

These are NOT in ARCHITECTURE.md but should be added:

#### A. Persistent Rule Tracking
**Problem**: In-memory map lost on agent restart
**Solution**:
```go
// Save to: C:\ProgramData\network-policy-agent\tracker.json
type PersistedTracker struct {
    Policies map[string][]RuleSet `json:"policies"`
}
```

#### B. Orphan Cleanup on Startup
**Problem**: Stale HCN rules if agent crashes
**Solution**:
```go
func (r *Reconciler) cleanupOrphans() {
    // 1. Load persisted tracker
    // 2. List current NetworkPolicies
    // 3. Find tracked policies that no longer exist
    // 4. Remove their HCN rules
}
```

#### C. podSelector Filtering (Future)
**Problem**: Currently applies rules to ALL endpoints, not just selected pods
**Solution**:
- Add pod informer with field selector (nodeName)
- Build index: podIP → pod labels
- Filter endpoints by matching podSelector before applying rules

## Next Steps After Plan Approval

1. **Initialize Project** (Phase 1):
   - Run `go mod init github.com/knabben/firewall-controller`
   - Add dependencies
   - Create directory structure

2. **Implement Core Logic** (Phases 2-5):
   - Converter → HCN Client → Reconciler → Main
   - Add tests at each stage

3. **Deploy & Test** (Phases 6-8):
   - Create manifests
   - Build Windows container
   - Test on real cluster

4. **Iterate** (Phase 9):
   - Add observability
   - Implement podSelector filtering
   - Performance tuning

## Open Questions

1. **Windows Path for Tracker**: Should we use `C:\ProgramData\network-policy-agent\tracker.json` instead of `/var/lib/`?
2. **HCN Network Targeting**: Should we target a specific HCN network (e.g., "nat") or all networks?
3. **Default Deny Behavior**: Should we implement default-deny when a NetworkPolicy selects a pod?
4. **Rule ID Tracking**: How to reliably track HCN policy IDs for precise removal? (hcsshim API research needed)
5. **Error Reporting**: Should we add a status field to NetworkPolicy (annotations)? Or just logs/metrics?
