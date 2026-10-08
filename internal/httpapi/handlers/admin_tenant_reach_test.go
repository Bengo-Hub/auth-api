package handlers

import (
	"testing"

	"github.com/bengobox/auth-api/internal/ent"
)

func strp(s string) *string { return &s }

func TestPickBroadcastContactsOrder(t *testing.T) {
	tn := &ent.Tenant{ContactEmail: strp("info@urbanloft.co.ke"), ContactPhone: strp("+254700111222")}
	hq := &ent.Outlet{Metadata: map[string]any{
		"contact_phones": []any{map[string]any{"label": "Front desk", "value": "0700333444"}},
		"email":          "branch@urbanloft.co.ke",
	}}
	admins := []reachPerson{
		{firstName: "Grace", emails: []string{"grace@urbanloft.co.ke"}, phones: []string{"+254711000001"}},
		{firstName: "Titus", owner: true, emails: []string{"titus@urbanloft.co.ke"}, phones: []string{"0722000002"}},
		{firstName: "Ann"}, // nothing verified: contributes nothing
	}
	// The tenant contact is a verified account address; the branch email belongs to nobody.
	emails, phones := pickBroadcastContacts(admins, tn, hq, map[string]bool{"info@urbanloft.co.ke": true})

	wantEmails := []string{"titus@urbanloft.co.ke", "grace@urbanloft.co.ke", "info@urbanloft.co.ke"}
	if len(emails) != len(wantEmails) {
		t.Fatalf("emails %+v", emails)
	}
	for i, w := range wantEmails {
		if emails[i].Address != w {
			t.Errorf("email %d = %s, want %s", i, emails[i].Address, w)
		}
	}
	if emails[0].Source != "owner" || emails[0].FirstName != "Titus" || !emails[0].Verified {
		t.Errorf("owner comes first, verified, greeted by name: %+v", emails[0])
	}
	if emails[2].Source != "tenant" || !emails[2].Verified {
		t.Errorf("a verified tenant contact is listed as verified: %+v", emails[2])
	}
	wantPhones := []string{"0722000002", "+254711000001", "+254700111222", "0700333444"}
	for i, w := range wantPhones {
		if phones[i].Address != w {
			t.Errorf("phone %d = %s, want %s", i, phones[i].Address, w)
		}
	}
}

func TestPickBroadcastContactsDedupesAndFallsBack(t *testing.T) {
	// The owner's verified phone is also the tenant phone: listed once, as the owner's.
	tn := &ent.Tenant{ContactPhone: strp("+254722000002")}
	admins := []reachPerson{{firstName: "Titus", owner: true, phones: []string{"0722000002"}}}
	_, phones := pickBroadcastContacts(admins, tn, nil, nil)
	if len(phones) != 1 || phones[0].Source != "owner" {
		t.Fatalf("phones %+v", phones)
	}
	// No admins with verified contacts: the tenant's own contact is used when it is verified.
	emails, _ := pickBroadcastContacts(nil, &ent.Tenant{ContactEmail: strp("Hello@Shop.ke")}, nil, map[string]bool{"hello@shop.ke": true})
	if len(emails) != 1 || emails[0].Source != "tenant" {
		t.Fatalf("emails %+v", emails)
	}
	// An unverified tenant contact email is never used.
	if emails, _ := pickBroadcastContacts(nil, &ent.Tenant{ContactEmail: strp("owner@gmail.com")}, nil, nil); len(emails) != 0 {
		t.Fatalf("unverified contact email must be left out: %+v", emails)
	}
}

func TestFirstNameOf(t *testing.T) {
	if f, full := firstNameOf(map[string]any{"name": "Titus Owuor"}); f != "Titus" || full != "Titus Owuor" {
		t.Errorf("got %q %q", f, full)
	}
	if f, _ := firstNameOf(map[string]any{"first_name": "Amina", "name": "A. Hassan"}); f != "Amina" {
		t.Errorf("first_name wins: %q", f)
	}
	if f, full := firstNameOf(map[string]any{}); f != "" || full != "" {
		t.Errorf("empty profile: %q %q", f, full)
	}
}
