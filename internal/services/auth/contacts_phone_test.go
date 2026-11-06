package auth

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/bengobox/auth-api/internal/ent/userphone"
)

// A person who signed in without a phone (Google, email) proves one: it lands verified and primary;
// a second proven number does not take over as primary; an unproven row on another account is taken
// over; a number another account has proven is refused and stays with that account.
func TestVerifyAndSetUserPhone(t *testing.T) {
	s, client, _ := newPhoneSignupTestService(t)
	ctx := context.Background()
	suffix := uuid.NewString()[:8]
	owner, _ := client.User.Create().SetEmail("owner-" + suffix + "@mail.test").SetStatus("active").Save(ctx)
	other, _ := client.User.Create().SetEmail("other-" + suffix + "@mail.test").SetStatus("active").Save(ctx)

	const first, second, typed, proven = "+254722100001", "+254722100002", "+254722100003", "+254722100004"

	if held, err := s.PhoneHeldByAnother(ctx, owner.ID, first); err != nil || held {
		t.Fatalf("a free number is not held: %v %v", held, err)
	}
	if err := s.VerifyAndSetUserPhone(ctx, owner.ID, first); err != nil {
		t.Fatal(err)
	}
	row := client.UserPhone.Query().Where(userphone.PhoneEQ(first)).OnlyX(ctx)
	if !row.IsVerified || !row.IsPrimary || row.VerifiedAt == nil || row.UserID != owner.ID {
		t.Fatalf("first number: %+v", row)
	}
	// Services read the phone from /auth/me's profile, so it must land there, once.
	if got := client.User.GetX(ctx, owner.ID).Profile["phone"]; got != first {
		t.Fatalf("profile phone %v, want %s", got, first)
	}
	if err := s.VerifyAndSetUserPhone(ctx, owner.ID, second); err != nil {
		t.Fatal(err)
	}
	if client.UserPhone.Query().Where(userphone.PhoneEQ(second)).OnlyX(ctx).IsPrimary {
		t.Fatal("a second number must not take over as primary")
	}
	if got := client.User.GetX(ctx, owner.ID).Profile["phone"]; got != first {
		t.Fatalf("a second number must not replace the profile phone: %v", got)
	}
	// Proving a number already on the account is idempotent.
	if err := s.VerifyAndSetUserPhone(ctx, owner.ID, first); err != nil {
		t.Fatal(err)
	}

	if _, err := s.AddUserPhone(ctx, other.ID, typed); err != nil {
		t.Fatal(err)
	}
	if held, err := s.PhoneHeldByAnother(ctx, owner.ID, typed); err != nil || held {
		t.Fatalf("an unproven number is not held: %v %v", held, err)
	}
	if err := s.VerifyAndSetUserPhone(ctx, owner.ID, typed); err != nil {
		t.Fatal(err)
	}
	if got := client.UserPhone.Query().Where(userphone.PhoneEQ(typed)).OnlyX(ctx); got.UserID != owner.ID || !got.IsVerified {
		t.Fatalf("the prover takes an unproven number: %+v", got)
	}

	if err := s.VerifyAndSetUserPhone(ctx, other.ID, proven); err != nil {
		t.Fatal(err)
	}
	if held, err := s.PhoneHeldByAnother(ctx, owner.ID, proven); err != nil || !held {
		t.Fatalf("a proven number is held: %v %v", held, err)
	}
	if err := s.VerifyAndSetUserPhone(ctx, owner.ID, proven); !errors.Is(err, ErrPhoneAlreadyExists) {
		t.Fatalf("a proven number must be refused, got %v", err)
	}
	if got := client.UserPhone.Query().Where(userphone.PhoneEQ(proven)).OnlyX(ctx); got.UserID != other.ID {
		t.Fatalf("a proven number stays with its holder: %+v", got)
	}
}
