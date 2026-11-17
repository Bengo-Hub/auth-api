package handlers

import (
	eventslib "github.com/Bengo-Hub/shared-events"
)

// APIKeyChangedTopic is the Broadcaster topic (namespace "auth") announcing that an API key or
// App token was revoked, rotated, suspended, deleted or had its scopes changed. The payload is
// the key's stored SHA-256 hash (never the key), which equals authclient.HashAPIKey, so every
// consuming service can call APIKeyValidator.InvalidateHash on every pod at once instead of
// serving the stale result until its cache TTL runs out.
const APIKeyChangedTopic = "apikey.changed"

var keyBroadcaster *eventslib.Broadcaster

// SetKeyBroadcaster wires the broadcaster used to announce key changes (nil disables it).
func SetKeyBroadcaster(b *eventslib.Broadcaster) { keyBroadcaster = b }

// publishKeyChanged sends one apikey.changed message. Tests replace it to see what was announced.
var publishKeyChanged = func(tenantID, payload string) {
	if keyBroadcaster == nil {
		return
	}
	_ = keyBroadcaster.Publish(APIKeyChangedTopic, tenantID, "", []byte(payload))
}

// announceKeyChanged tells every service to drop cached validation results for these hashes.
func announceKeyChanged(tenantID string, hashes ...string) {
	for _, h := range hashes {
		if h != "" {
			publishKeyChanged(tenantID, h)
		}
	}
}
