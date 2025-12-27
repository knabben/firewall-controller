//go:build windows

package controller

import (
	"context"
	"time"

	"github.com/go-logr/logr"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/knabben/firewall-controller/internal/converter"
	hcnpkg "github.com/knabben/firewall-controller/internal/hcn"
)

// NetworkPolicyReconciler reconciles NetworkPolicy objects and applies HCN ACL rules
type NetworkPolicyReconciler struct {
	client.Client
	Scheme     *runtime.Scheme
	HCNManager *hcnpkg.Manager
	NodeName   string // Name of the node this agent is running on
}

// Reconcile implements the reconciliation loop for NetworkPolicy resources
// It converts NetworkPolicy rules to HCN ACL rules and applies them to all endpoints
func (r *NetworkPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	logger.Info("Reconciling NetworkPolicy", "namespace", req.Namespace, "name", req.Name)

	// Fetch the NetworkPolicy
	var np networkingv1.NetworkPolicy
	if err := r.Get(ctx, req.NamespacedName, &np); err != nil {
		if apierrors.IsNotFound(err) {
			// NetworkPolicy was deleted, clean up HCN rules
			logger.Info("NetworkPolicy not found, cleaning up HCN rules",
				"namespace", req.Namespace,
				"name", req.Name)
			return r.reconcileDelete(ctx, req.NamespacedName.String())
		}
		logger.Error(err, "Failed to get NetworkPolicy")
		return ctrl.Result{}, err
	}

	// Convert NetworkPolicy to HCN ACL rules
	logger.V(1).Info("Converting NetworkPolicy to HCN ACL rules",
		"ingressRules", len(np.Spec.Ingress),
		"egressRules", len(np.Spec.Egress))

	rules := converter.NetworkPolicyToACLRules(&np)

	logger.Info("Generated ACL rules from NetworkPolicy",
		"ruleCount", len(rules))

	// Apply ACL rules via HCN Manager
	policyKey := req.NamespacedName.String() // e.g., "default/allow-http"
	if err := r.HCNManager.ApplyACLRules(policyKey, rules); err != nil {
		logger.Error(err, "Failed to apply HCN ACL rules",
			"policyKey", policyKey,
			"ruleCount", len(rules))

		// Requeue with backoff - transient errors like endpoint unavailability
		// will be retried automatically by controller-runtime
		return ctrl.Result{RequeueAfter: 30 * time.Second}, err
	}

	logger.Info("Successfully applied HCN ACL rules",
		"policyKey", policyKey,
		"ruleCount", len(rules))

	return ctrl.Result{}, nil
}

// reconcileDelete handles cleanup when a NetworkPolicy is deleted
func (r *NetworkPolicyReconciler) reconcileDelete(ctx context.Context, policyKey string) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	logger.Info("Reconciling NetworkPolicy deletion", "policyKey", policyKey)

	// Remove HCN ACL rules
	if err := r.HCNManager.RemoveACLRules(policyKey); err != nil {
		logger.Error(err, "Failed to remove HCN ACL rules", "policyKey", policyKey)
		// Still return success - the policy is gone, so we don't want to keep retrying
		// The HCN rules will be cleaned up on agent restart via orphan cleanup
		return ctrl.Result{}, nil
	}

	logger.Info("Successfully removed HCN ACL rules", "policyKey", policyKey)
	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager
func (r *NetworkPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&networkingv1.NetworkPolicy{}).
		Complete(r)
}

// NewNetworkPolicyReconciler creates a new NetworkPolicyReconciler
func NewNetworkPolicyReconciler(
	client client.Client,
	scheme *runtime.Scheme,
	hcnManager *hcnpkg.Manager,
	nodeName string,
	logger logr.Logger,
) *NetworkPolicyReconciler {
	return &NetworkPolicyReconciler{
		Client:     client,
		Scheme:     scheme,
		HCNManager: hcnManager,
		NodeName:   nodeName,
	}
}
