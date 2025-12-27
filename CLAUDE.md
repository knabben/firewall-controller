# Kubernetes Controller Development Guide
## Build Commands

```bash
make build       # Build binary
make test        # Run tests
make run         # Run locally
make manifests   # Generate CRDs
make generate    # Generate DeepCopy
make install     # Install CRDs
```

## Project Structure
```
api/v1/              → CRD types (*_types.go)
internal/controller/ → Reconcilers (*_controller.go)
cmd/main.go          → Manager setup
config/crd/          → Generated CRD YAML
```

## CRD Types
Define in `api/v1/<resource>_types.go`:

- Spec = desired state (user input)
- Status = observed state (controller output)
- Always add `// +kubebuilder:object:root=true` and `// +kubebuilder:subresource:status`

Key markers:
- `// +kubebuilder:validation:Required`
- `// +kubebuilder:validation:Minimum=1`
- `// +kubebuilder:default=value`
- `// +optional`

After changes: `make generate && make manifests`

## client-go Internals
**Components:**
- Informer = List + Watch, maintains local cache
- Lister = read from cache (fast)
- Work Queue = deduplication + rate limiting + retry
- Clientset = typed CRUD operations

**Informer flow:**
API Server → Reflector → Delta FIFO → Indexer → Event Handlers

**Work Queue rate limiting:**
- Per-item: 5ms → 10ms → 20ms → ... → 1000s max
- Overall: 10 qps, 100 burst

## controller-runtime Architecture
**Manager provides:**
- Shared Cache (reads from cache, writes to API)
- Client, Scheme, Metrics, Health Probes, Leader Election

**Reconciler returns:**
- `ctrl.Result{}, nil` → success, done
- `ctrl.Result{Requeue: true}, nil` → retry now
- `ctrl.Result{RequeueAfter: time}, nil` → retry later
- `ctrl.Result{}, err` → retry with backoff

**Builder pattern:**
- `For(&MyResource{})` → primary resource
- `Owns(&ConfigMap{})` → owned resources (auto-enqueue owner)
- `Watches(&Secret{}, handler)` → custom watch


## Reconciler Structure
1. Fetch primary resource → NotFound? Return nil (deleted)
2. Check DeletionTimestamp → Being deleted? Run cleanup, remove finalizer
3. Add finalizer if missing
4. Reconcile child resources → Use CreateOrUpdate + SetControllerReference
5. Update status → Set conditions, observedGeneration, ready flag
```
## Essential Patterns
**Finalizers:**
- Add: `controllerutil.AddFinalizer(obj, name)`
- Remove: `controllerutil.RemoveFinalizer(obj, name)`
- Check: `controllerutil.ContainsFinalizer(obj, name)`

**Owner References:**
- `controllerutil.SetControllerReference(owner, owned, scheme)`
- Enables garbage collection when owner deleted

**CreateOrUpdate:**
- `controllerutil.CreateOrUpdate(ctx, client, obj, mutateFn)`
- Handles both create and update idempotently

**Status Conditions:**
- `meta.SetStatusCondition(&status.Conditions, condition)`
- Types: Ready, Progressing, Degraded

**Server-Side Apply:**
- `client.Patch(ctx, obj, client.Apply, client.FieldOwner("controller-name"))`

## Error Handling
| Error Type | Action |
|------------|--------|
| NotFound (primary) | Return nil |
| NotFound (dependency) | Update status, requeue later |
| Conflict | Requeue immediately |
| Transient (timeout) | Return error (backoff retry) |
| User error (bad spec) | Update status, don't retry |

## Testing with envtest
- Uses real API server (etcd + kube-apiserver)
- Load CRDs from `config/crd/bases`
- Use `Eventually()` for async assertions
- Cleanup resources after each test

## RBAC Markers
```go
// +kubebuilder:rbac:groups=mygroup,resources=myresources,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=mygroup,resources=myresources/status,verbs=get;update;patch
// +kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch;create;update;patch;delete
```

Run `make manifests` to generate `config/rbac/role.yaml`

## Code Style
1. Use `log.FromContext(ctx)` for structured logging
2. Prefer Server-Side Apply over Update
3. Always set owner references on created resources
4. Use finalizers for external cleanup
5. Update `status.observedGeneration` on every reconcile
6. Handle NotFound gracefully
7. Return errors for transient failures only
8. Update status (not error) for user mistakes

## Workflow
1. **Explore** → Read existing patterns first
2. **Plan** → Think through reconciliation logic
3. **Implement** → Run `make build` after each section
4. **Test** → Write envtest integration tests
5. **Verify** → Run `make run` against cluster
6. **Commit** → Small, focused commits
