package handlers

import (
	"context"
	"net/http"
	"time"

	k8sclient "github.com/bengobox/auth-api/internal/clients/k8s"
	authmiddleware "github.com/bengobox/auth-api/internal/httpapi/middleware"
	"go.uber.org/zap"
)

// K8sMonitorHandler serves the platform infrastructure monitoring dashboard
// (replaces the removed Prometheus/Grafana stack). Platform-owner only —
// this exposes cluster-wide node/pod/namespace/cronjob state.
type K8sMonitorHandler struct {
	client *k8sclient.Client // nil outside the cluster (e.g. local dev)
	logger *zap.Logger
}

// NewK8sMonitorHandler builds the handler. client may be nil (e.g. local dev
// where there's no in-cluster ServiceAccount token); the handler then
// responds 503 instead of failing to construct.
func NewK8sMonitorHandler(client *k8sclient.Client, logger *zap.Logger) *K8sMonitorHandler {
	return &K8sMonitorHandler{client: client, logger: logger.Named("k8s_monitor_handler")}
}

func (h *K8sMonitorHandler) requirePlatformAdmin(r *http.Request) bool {
	claims, ok := authmiddleware.ClaimsFromContext(r.Context())
	return ok && claims != nil && claims.IsPlatformOwner
}

// Overview handles GET /api/v1/admin/platform-monitor/overview.
func (h *K8sMonitorHandler) Overview(w http.ResponseWriter, r *http.Request) {
	if !h.requirePlatformAdmin(r) {
		writeError(w, http.StatusForbidden, "forbidden", "platform admin required", nil)
		return
	}
	if h.client == nil {
		writeError(w, http.StatusServiceUnavailable, "unavailable", "cluster monitoring is not available in this environment", nil)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()

	overview, err := h.client.Overview(ctx)
	if err != nil {
		h.logger.Error("cluster overview failed", zap.Error(err))
		writeError(w, http.StatusBadGateway, "cluster_query_failed", "failed to query cluster state", nil)
		return
	}

	writeJSON(w, http.StatusOK, overview)
}
