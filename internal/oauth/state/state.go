package state

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Payload captures OAuth state metadata.
type Payload struct {
	TenantSlug  string `json:"tenant_slug"`
	ClientID    string `json:"client_id"`
	Flow        string `json:"flow"`
	RedirectURI string `json:"redirect_uri"`
	Nonce       string `json:"nonce"`
	// ReturnTo is where to send the person after sign-in (the app's authorize URL, or a relative
	// path). It is validated before it is stored, so the state never carries an arbitrary URL.
	ReturnTo string `json:"return_to,omitempty"`
	// Defaulted is true when no organisation was named and the platform tenant was used as a
	// placeholder: a person who belongs elsewhere then signs in to their own tenant instead.
	Defaulted bool `json:"defaulted,omitempty"`
}

// Encode signs the payload using HS256.
func Encode(secret string, payload Payload, ttl time.Duration) (string, error) {
	if secret == "" {
		return "", fmt.Errorf("oauth state secret missing")
	}
	now := time.Now()
	claims := jwt.MapClaims{
		"tenant_slug":  payload.TenantSlug,
		"client_id":    payload.ClientID,
		"flow":         payload.Flow,
		"redirect_uri": payload.RedirectURI,
		"nonce":        payload.Nonce,
		"iat":          now.Unix(),
		"exp":          now.Add(ttl).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}

// Decode verifies and extracts the payload.
func Decode(secret string, token string) (*Payload, error) {
	if secret == "" {
		return nil, fmt.Errorf("oauth state secret missing")
	}
	parsed, err := jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return []byte(secret), nil
	})
	if err != nil {
		return nil, fmt.Errorf("parse state: %w", err)
	}
	if !parsed.Valid {
		return nil, fmt.Errorf("state token invalid")
	}
	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("state claims invalid")
	}
	payload := &Payload{
		TenantSlug:  claimString(claims, "tenant_slug"),
		ClientID:    claimString(claims, "client_id"),
		Flow:        claimString(claims, "flow"),
		RedirectURI: claimString(claims, "redirect_uri"),
		Nonce:       claimString(claims, "nonce"),
	}
	return payload, nil
}

func claimString(claims jwt.MapClaims, key string) string {
	if v, ok := claims[key]; ok && v != nil {
		return fmt.Sprintf("%v", v)
	}
	return ""
}
