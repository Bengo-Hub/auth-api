package state

import (
	"testing"
	"time"
)

const testSecret = "unit-test-secret-not-a-real-one"

func TestRoundTripKeepsEveryField(t *testing.T) {
	in := Payload{
		TenantSlug:  "urban-loft",
		ClientID:    "ordering-ui",
		Flow:        "login",
		RedirectURI: "https://example.test/cb",
		Nonce:       "n1",
		ReturnTo:    "https://sso.codevertexafrica.com/api/v1/authorize?client_id=ordering-ui",
		Defaulted:   true,
	}
	tok, err := Encode(testSecret, in, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	out, err := Decode(testSecret, tok)
	if err != nil {
		t.Fatal(err)
	}
	if *out != in {
		t.Fatalf("round trip lost data:\n in  %+v\n out %+v", in, *out)
	}
}

func TestChallengeCarriesPurposeAndUser(t *testing.T) {
	tok, err := Encode(testSecret, Payload{Purpose: PurposeSocialMFA, UserID: "u-1", Nonce: "n2"}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	out, err := Decode(testSecret, tok)
	if err != nil {
		t.Fatal(err)
	}
	if out.Purpose != PurposeSocialMFA || out.UserID != "u-1" {
		t.Fatalf("challenge fields lost: %+v", *out)
	}
}

func TestOAuthStateHasNoPurpose(t *testing.T) {
	tok, _ := Encode(testSecret, Payload{TenantSlug: "t", Nonce: "n3"}, time.Minute)
	out, err := Decode(testSecret, tok)
	if err != nil {
		t.Fatal(err)
	}
	if out.Purpose != "" {
		t.Fatalf("a provider state must not look like an MFA challenge, got purpose %q", out.Purpose)
	}
}

func TestWrongSecretAndExpiryRejected(t *testing.T) {
	tok, _ := Encode(testSecret, Payload{Nonce: "n4"}, time.Minute)
	if _, err := Decode("another-secret", tok); err == nil {
		t.Fatal("a token signed with a different secret must not decode")
	}
	expired, _ := Encode(testSecret, Payload{Nonce: "n5"}, -time.Minute)
	if _, err := Decode(testSecret, expired); err == nil {
		t.Fatal("an expired token must not decode")
	}
}
