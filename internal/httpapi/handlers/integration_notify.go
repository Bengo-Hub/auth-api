package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/bengobox/auth-api/internal/services/integrations"
	"go.uber.org/zap"
)

// EtimsSupportNotifier fires the Slack + email notification when a tenant or external lead
// requests an integration (starting with eTIMS). Resolves its destination from the SAME
// platform_alert_channels IntegrationConfig row the Infrastructure Monitor page already edits
// (see admin_handler.go's platformAlertChannelsIntegrationName) — two new optional keys,
// etims_support_slack_webhook_url / etims_support_email_to, falling back to the general
// slack_webhook_url / alert_email_to when unset, so this never requires separate setup to work.
// Both channels are best-effort: a missing/unreachable destination never fails the caller's
// request (mirrors fleet-health-watcher's own "degrade, don't block" posture for the same reason —
// this fires from a user-facing request-submission flow, not a background job).
type EtimsSupportNotifier struct {
	integrations *integrations.Service
	notifBaseURL string
	notifAPIKey  string
	httpClient   *http.Client
	log          *zap.Logger
}

// NewEtimsSupportNotifier builds the notifier. notifAPIKey is the shared INTERNAL_SERVICE_KEY,
// sent as X-API-Key to notifications-api — the same S2S credential every other service already
// uses to call it (see notifications-api's own auth check).
func NewEtimsSupportNotifier(store *integrations.Service, notificationsBaseURL, notifAPIKey string, log *zap.Logger) *EtimsSupportNotifier {
	return &EtimsSupportNotifier{
		integrations: store,
		notifBaseURL: notificationsBaseURL,
		notifAPIKey:  notifAPIKey,
		httpClient:   &http.Client{Timeout: 8 * time.Second},
		log:          log.Named("etims-support-notifier"),
	}
}

// EtimsSupportNotification carries the details to surface to the support team.
type EtimsSupportNotification struct {
	RequestType     string
	IntegrationMode string
	CompanyName     string
	RequesterName   string
	RequesterEmail  string
	RequesterPhone  string
	TenantID        string // empty for an external lead with no tenant yet
	Source          string
	Notes           string
}

// Notify sends the Slack + email alert. Errors are logged, never returned — see doc comment.
func (n *EtimsSupportNotifier) Notify(ctx context.Context, d EtimsSupportNotification) {
	creds, err := n.integrations.GetDecryptedConfig(ctx, nil, platformAlertChannelsIntegrationName)
	if err != nil {
		creds = map[string]string{}
	}

	webhook := creds["etims_support_slack_webhook_url"]
	if webhook == "" {
		webhook = creds["slack_webhook_url"]
	}
	emailTo := creds["etims_support_email_to"]
	if emailTo == "" {
		emailTo = creds["alert_email_to"]
	}

	if webhook != "" {
		n.sendSlack(ctx, webhook, d)
	}
	if len(splitEmails(emailTo)) > 0 {
		n.sendEmail(ctx, emailTo, d)
	} else {
		n.log.Warn("integration request alert not emailed: no etims_support_email_to or alert_email_to in platform_alert_channels",
			zap.String("request_type", d.RequestType))
	}
}

func (n *EtimsSupportNotifier) sendSlack(ctx context.Context, webhook string, d EtimsSupportNotification) {
	text := ":globe_with_meridians: New integration request (" + d.RequestType + ", " + d.IntegrationMode + ")\n" +
		"Company: " + orDash(d.CompanyName) + "\n" +
		"Contact: " + orDash(d.RequesterName) + " <" + orDash(d.RequesterEmail) + "> " + orDash(d.RequesterPhone) + "\n" +
		"Source: " + orDash(d.Source) + " · Tenant: " + orDash(d.TenantID) + "\n" +
		"Notes: " + orDash(d.Notes)
	body, _ := json.Marshal(map[string]string{"text": text})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhook, bytes.NewReader(body))
	if err != nil {
		n.log.Warn("build slack request failed", zap.Error(err))
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := n.httpClient.Do(req)
	if err != nil {
		n.log.Warn("slack notify failed", zap.Error(err))
		return
	}
	_ = resp.Body.Close()
}

// integrationRequestLabels are the plain names of the request types the Vera form and the
// developer portal send, for the team alert. An unlisted type is shown as stored.
var integrationRequestLabels = map[string]string{
	"etims_integration":            "KRA eTIMS invoicing",
	"payments_integration":         "M-Pesa, Airtel Money or card payments",
	"notifications_integration":    "SMS, WhatsApp or email sending",
	"sso_integration":              "Sign in with Codevertex (SSO)",
	"api_integration":              "Their app or website on our POS, stock or order APIs",
	"data_import":                  "Moving data from another system",
	"printing_hardware":            "Barcode, label or receipt printers",
	"truload_weighing":             "Weighbridges and number-plate cameras",
	"camera_systems":               "CCTV and security cameras",
	"plc_automation":               "Machines, sensors and PLCs",
	"arduino_iot":                  "Machines, sensors and PLCs",
	"other_integration":            "Something else, or not sure",
	"service_access_treasury":      "API access: Treasury and eTIMS",
	"service_access_notifications": "API access: Notifications",
	"service_access_sso":           "API access: Codevertex sign-in (SSO)",
}

func integrationRequestLabel(requestType string) string {
	if l, ok := integrationRequestLabels[requestType]; ok {
		return l
	}
	return requestType
}

func (n *EtimsSupportNotifier) sendEmail(ctx context.Context, to string, d EtimsSupportNotification) {
	label := integrationRequestLabel(d.RequestType)
	payload := map[string]any{
		"channel":  "email",
		"tenant":   "codevertex",
		"template": "platform/etims_integration_request",
		"to":       splitEmails(to),
		"data": map[string]any{
			"request_label":    label,
			"request_type":     d.RequestType,
			"integration_mode": d.IntegrationMode,
			"company_name":     d.CompanyName,
			"requester_name":   d.RequesterName,
			"requester_email":  d.RequesterEmail,
			"requester_phone":  d.RequesterPhone,
			"tenant_id":        d.TenantID,
			"source":           d.Source,
			"notes":            d.Notes,
		},
		"metadata": map[string]string{"subject": "New integration request: " + label},
	}
	body, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.notifBaseURL+"/api/v1/notifications/messages", bytes.NewReader(body))
	if err != nil {
		n.log.Warn("build notifications-api request failed", zap.Error(err))
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if n.notifAPIKey != "" {
		req.Header.Set("X-API-Key", n.notifAPIKey)
	}
	resp, err := n.httpClient.Do(req)
	if err != nil {
		n.log.Warn("email notify failed", zap.Error(err))
		return
	}
	if resp.StatusCode >= 300 {
		n.log.Warn("email notify refused by notifications-api", zap.Int("status", resp.StatusCode),
			zap.String("request_type", d.RequestType))
	}
	_ = resp.Body.Close()
}

// DeveloperProvisioned carries what the newly-provisioned developer needs in their
// approval email.
type DeveloperProvisioned struct {
	RequesterName  string
	RequesterEmail string
	TenantSlug     string
	// ClientID is the sandbox app's public consumer key. No secret or API key is ever put in
	// the email; the developer issues those in the console (ConsoleURL), shown once there.
	ClientID   string
	ConsoleURL string
	DocsURL    string
}

// NotifyDeveloperProvisioned emails the REQUESTER (not staff) that their sandbox app is ready
// once auto-provisioning completes. Same best-effort posture as Notify: a delivery failure
// here must never undo the tenant/App that were already created.
func (n *EtimsSupportNotifier) NotifyDeveloperProvisioned(ctx context.Context, d DeveloperProvisioned) {
	payload := map[string]any{
		"channel":  "email",
		"tenant":   "codevertex",
		"template": "platform/developer_provisioned",
		"to":       []string{d.RequesterEmail},
		"data": map[string]any{
			"requester_name": d.RequesterName,
			"tenant_slug":    d.TenantSlug,
			"client_id":      d.ClientID,
			"console_url":    d.ConsoleURL,
			"docs_url":       d.DocsURL,
		},
		"metadata": map[string]string{"subject": "Your Codevertex developer access is ready"},
	}
	body, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.notifBaseURL+"/api/v1/notifications/messages", bytes.NewReader(body))
	if err != nil {
		n.log.Warn("build developer-provisioned request failed", zap.Error(err))
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if n.notifAPIKey != "" {
		req.Header.Set("X-API-Key", n.notifAPIKey)
	}
	resp, err := n.httpClient.Do(req)
	if err != nil {
		n.log.Warn("developer-provisioned email failed", zap.Error(err), zap.String("to", d.RequesterEmail))
		return
	}
	_ = resp.Body.Close()
}

// splitEmails reads the alert setting as a comma separated list, so several people on the
// team can get the alert; blanks are dropped.
func splitEmails(list string) []string {
	var out []string
	for _, part := range strings.Split(list, ",") {
		if addr := strings.TrimSpace(part); addr != "" {
			out = append(out, addr)
		}
	}
	return out
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}
