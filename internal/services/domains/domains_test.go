package domains

import (
	"strings"
	"testing"
)

func TestNormaliseHostname(t *testing.T) {
	ok := map[string]string{
		"Shop.Example.co.ke":                 "shop.example.co.ke",
		"https://alphachinamarket.co.ke/x?y": "alphachinamarket.co.ke",
		"urbaneats.theurbanloftcafe.com:443": "urbaneats.theurbanloftcafe.com",
		"store.example.com.":                 "store.example.com",
	}
	for in, want := range ok {
		got, err := NormaliseHostname(in)
		if err != nil || got != want {
			t.Errorf("%q -> %q, %v; want %q", in, got, err, want)
		}
	}
	bad := map[string]error{
		"":                                       ErrInvalidHostname,
		"localhost":                              ErrInvalidHostname,
		"203.0.113.10":                           ErrInvalidHostname,
		"bad_host.com":                           ErrInvalidHostname,
		"-x.example.com":                         ErrInvalidHostname,
		"shop.codevertexafrica.com":              ErrReservedHost,
		"codevertexafrica.com":                   ErrReservedHost,
		"erp.masterspace.co.ke":                  ErrReservedHost,
		"x." + strings.Repeat("a", 250) + ".com": ErrInvalidHostname,
	}
	for in, want := range bad {
		if _, err := NormaliseHostname(in); err != want {
			t.Errorf("%q -> %v, want %v", in, err, want)
		}
	}
}

func TestObjectNameIsStableAndValid(t *testing.T) {
	a := objectName("alphachinamarket.co.ke")
	if a != objectName("alphachinamarket.co.ke") {
		t.Fatal("name must be stable")
	}
	if a == objectName("www.alphachinamarket.co.ke") {
		t.Fatal("different hosts must get different names")
	}
	long := objectName(strings.Repeat("abcdefghij.", 20) + "example.com")
	if len(long)+len("-tls") > 63 || !strings.HasPrefix(long, "td-") {
		t.Fatalf("name %q too long or unprefixed", long)
	}
	for _, c := range a {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			t.Fatalf("invalid character in %q", a)
		}
	}
}

func TestCatalogue(t *testing.T) {
	o, ok := Target("ordering")
	if !ok || o.Namespace != "ordering" || o.Service != "ordering-frontend" || o.OAuthClientID != "ordering-ui" {
		t.Fatalf("ordering target = %+v", o)
	}
	if _, ok := Target("nope"); ok {
		t.Fatal("unknown service must not resolve")
	}
	ns := Namespaces()
	for i := 1; i < len(ns); i++ {
		if ns[i-1] >= ns[i] {
			t.Fatalf("namespaces not unique and sorted: %v", ns)
		}
	}
}
