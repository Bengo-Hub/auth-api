package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	authmiddleware "github.com/bengobox/auth-api/internal/httpapi/middleware"
	"go.uber.org/zap"
)

// SealedSecretsHandler lets a platform admin check the status of, and trigger a rotate/backup-
// refresh for, the devops-k8s cluster's Sealed Secrets master key — via the GitHub Actions API,
// never by auth-api touching the cluster or the key material directly. See
// sealed-secrets-key-rotate.yml in devops-k8s for what actually runs, and
// gap-analysis-and-remediation-plan.md item 14 for why this exists (the key had never been
// backed up before 2026-08-21; losing it would make every SealedSecret in the repo permanently
// undecryptable).
type SealedSecretsHandler struct {
	httpClient *http.Client
	token      string // fine-grained PAT, Actions:write only on devops-k8s — empty in envs without it configured
	owner      string
	repo       string
	workflow   string
	logger     *zap.Logger
}

func NewSealedSecretsHandler(token, owner, repo string, logger *zap.Logger) *SealedSecretsHandler {
	return &SealedSecretsHandler{
		httpClient: &http.Client{Timeout: 15 * time.Second},
		token:      token,
		owner:      owner,
		repo:       repo,
		workflow:   "sealed-secrets-key-rotate.yml",
		logger:     logger.Named("sealed_secrets_handler"),
	}
}

func (h *SealedSecretsHandler) requirePlatformAdmin(r *http.Request) bool {
	claims, ok := authmiddleware.ClaimsFromContext(r.Context())
	return ok && claims != nil && claims.IsPlatformOwner
}

func (h *SealedSecretsHandler) githubRequest(ctx context.Context, method, path string, body any) (*http.Response, error) {
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reader = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, "https://api.github.com"+path, reader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+h.token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return h.httpClient.Do(req)
}

// Status handles GET /api/v1/admin/infra/sealed-secrets/status. Returns only metadata (when the
// GitHub secret backing up the key was last created/updated) — never the key material itself,
// which GitHub's API never exposes for secrets in the first place.
func (h *SealedSecretsHandler) Status(w http.ResponseWriter, r *http.Request) {
	if !h.requirePlatformAdmin(r) {
		writeError(w, http.StatusForbidden, "forbidden", "platform admin required", nil)
		return
	}
	if h.token == "" {
		writeJSON(w, http.StatusOK, map[string]any{
			"configured": false,
			"message":    "DEVOPS_REPO_TOKEN is not set — rotate/refresh-backup is unavailable until a fine-grained PAT (Actions: write only, scoped to devops-k8s) is configured.",
		})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	resp, err := h.githubRequest(ctx, http.MethodGet, fmt.Sprintf("/repos/%s/%s/actions/secrets/SEALED_SECRETS_MASTER_KEY", h.owner, h.repo), nil)
	if err != nil {
		h.logger.Error("github secret status query failed", zap.Error(err))
		writeError(w, http.StatusBadGateway, "github_query_failed", "failed to query GitHub", nil)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		writeJSON(w, http.StatusOK, map[string]any{
			"configured":     true,
			"backup_exists":  false,
			"backup_warning": "No SEALED_SECRETS_MASTER_KEY GitHub secret found — the sealed-secrets master key has never been backed up. Trigger a refresh_backup run below before this matters.",
		})
		return
	}
	if resp.StatusCode != http.StatusOK {
		detail, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		h.logger.Error("github secret status non-200", zap.Int("status", resp.StatusCode), zap.String("body", string(detail)))
		writeError(w, http.StatusBadGateway, "github_query_failed", "GitHub API returned an unexpected status", nil)
		return
	}

	var meta struct {
		CreatedAt string `json:"created_at"`
		UpdatedAt string `json:"updated_at"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&meta); err != nil {
		writeError(w, http.StatusBadGateway, "github_decode_failed", "failed to parse GitHub response", nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"configured":     true,
		"backup_exists":  true,
		"backup_created": meta.CreatedAt,
		"backup_updated": meta.UpdatedAt,
	})
}

// Rotate handles POST /api/v1/admin/infra/sealed-secrets/rotate. Body: {"action": "refresh_backup"
// | "rotate"}. Dispatches sealed-secrets-key-rotate.yml via the GitHub Actions API — auth-api
// never touches the cluster or the key material for this at all, only tells GitHub to run the
// workflow that does.
func (h *SealedSecretsHandler) Rotate(w http.ResponseWriter, r *http.Request) {
	if !h.requirePlatformAdmin(r) {
		writeError(w, http.StatusForbidden, "forbidden", "platform admin required", nil)
		return
	}
	if h.token == "" {
		writeError(w, http.StatusServiceUnavailable, "not_configured", "DEVOPS_REPO_TOKEN is not set — rotate/refresh-backup is unavailable", nil)
		return
	}

	var body struct {
		Action string `json:"action"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<12)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body", "expected {\"action\": \"refresh_backup\"|\"rotate\"}", nil)
		return
	}
	if body.Action != "refresh_backup" && body.Action != "rotate" {
		writeError(w, http.StatusBadRequest, "invalid_action", "action must be refresh_backup or rotate", nil)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	dispatchBody := map[string]any{
		"ref":    "main",
		"inputs": map[string]string{"action": body.Action},
	}
	resp, err := h.githubRequest(ctx, http.MethodPost,
		fmt.Sprintf("/repos/%s/%s/actions/workflows/%s/dispatches", h.owner, h.repo, h.workflow), dispatchBody)
	if err != nil {
		h.logger.Error("github workflow dispatch failed", zap.Error(err))
		writeError(w, http.StatusBadGateway, "github_dispatch_failed", "failed to reach GitHub", nil)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		detail, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		h.logger.Error("github workflow dispatch non-2xx", zap.Int("status", resp.StatusCode), zap.String("body", string(detail)))
		writeError(w, http.StatusBadGateway, "github_dispatch_failed", "GitHub rejected the dispatch request", nil)
		return
	}

	h.logger.Info("sealed-secrets workflow dispatched", zap.String("action", body.Action))
	writeJSON(w, http.StatusAccepted, map[string]any{
		"dispatched": true,
		"action":     body.Action,
		"message":    "Workflow dispatched — check the Actions tab in devops-k8s for progress (usually completes in under a minute).",
	})
}
