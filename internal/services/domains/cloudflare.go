package domains

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const cloudflareAPI = "https://api.cloudflare.com/client/v4"

// cloudflare is the small slice of the Cloudflare API the reconciler needs: find the zone that
// holds a hostname and keep one DNS-only A record for it. DNS-only so cert-manager's HTTP-01
// challenge reaches the cluster.
type cloudflare struct {
	token string
	http  *http.Client

	mu       sync.Mutex
	zones    map[string]string // zone name -> id
	zonesAt  time.Time
	zonesTTL time.Duration
}

func newCloudflare(token string) *cloudflare {
	if strings.TrimSpace(token) == "" {
		return nil
	}
	return &cloudflare{token: token, http: &http.Client{Timeout: 20 * time.Second}, zonesTTL: 10 * time.Minute}
}

type cfEnvelope struct {
	Success bool              `json:"success"`
	Errors  []json.RawMessage `json:"errors"`
	Result  json.RawMessage   `json:"result"`
}

func (c *cloudflare) do(ctx context.Context, method, path string, body any, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, cloudflareAPI+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("cloudflare %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	var env cfEnvelope
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&env); err != nil {
		return fmt.Errorf("cloudflare %s %s: status %d: %w", method, path, resp.StatusCode, err)
	}
	if !env.Success {
		return fmt.Errorf("cloudflare %s %s: status %d: %s", method, path, resp.StatusCode, joinRaw(env.Errors))
	}
	if out != nil {
		return json.Unmarshal(env.Result, out)
	}
	return nil
}

func joinRaw(errs []json.RawMessage) string {
	parts := make([]string, 0, len(errs))
	for _, e := range errs {
		parts = append(parts, string(e))
	}
	return strings.Join(parts, "; ")
}

// zoneFor returns the id of the account zone that holds host (longest matching zone name), or ""
// when the hostname's DNS is not in our account.
func (c *cloudflare) zoneFor(ctx context.Context, host string) (string, string, error) {
	c.mu.Lock()
	stale := c.zones == nil || time.Since(c.zonesAt) > c.zonesTTL
	c.mu.Unlock()
	if stale {
		var res []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		}
		if err := c.do(ctx, http.MethodGet, "/zones?per_page=50", nil, &res); err != nil {
			return "", "", err
		}
		zones := make(map[string]string, len(res))
		for _, z := range res {
			zones[strings.ToLower(z.Name)] = z.ID
		}
		c.mu.Lock()
		c.zones, c.zonesAt = zones, time.Now()
		c.mu.Unlock()
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	best, bestID := "", ""
	for name, id := range c.zones {
		if (host == name || strings.HasSuffix(host, "."+name)) && len(name) > len(best) {
			best, bestID = name, id
		}
	}
	return bestID, best, nil
}

type cfRecord struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	Proxied bool   `json:"proxied"`
}

// upsertA makes host an A record to ip (DNS-only) and returns its record id. An existing A record
// for the host is updated in place; a CNAME at the same name is left alone and reported, since
// replacing it could break something the tenant set up.
func (c *cloudflare) upsertA(ctx context.Context, zoneID, host, ip string) (string, error) {
	var existing []cfRecord
	if err := c.do(ctx, http.MethodGet, "/zones/"+zoneID+"/dns_records?name="+url.QueryEscape(host), nil, &existing); err != nil {
		return "", err
	}
	body := map[string]any{"type": "A", "name": host, "content": ip, "ttl": 1, "proxied": false,
		"comment": "Codevertex tenant domain (auth-api domains)"}
	for _, r := range existing {
		switch r.Type {
		case "A":
			if r.Content == ip && !r.Proxied {
				return r.ID, nil
			}
			var out cfRecord
			if err := c.do(ctx, http.MethodPatch, "/zones/"+zoneID+"/dns_records/"+r.ID, body, &out); err != nil {
				return "", err
			}
			return out.ID, nil
		case "CNAME", "AAAA":
			return "", fmt.Errorf("%s already has a %s record; remove it in Cloudflare so the domain can point at the platform", host, r.Type)
		}
	}
	var out cfRecord
	if err := c.do(ctx, http.MethodPost, "/zones/"+zoneID+"/dns_records", body, &out); err != nil {
		return "", err
	}
	return out.ID, nil
}

// deleteRecord removes a record we created. A record that is already gone is not an error.
func (c *cloudflare) deleteRecord(ctx context.Context, zoneID, recordID string) error {
	if zoneID == "" || recordID == "" {
		return nil
	}
	err := c.do(ctx, http.MethodDelete, "/zones/"+zoneID+"/dns_records/"+recordID, nil, nil)
	if err != nil && strings.Contains(err.Error(), "status 404") {
		return nil
	}
	return err
}
