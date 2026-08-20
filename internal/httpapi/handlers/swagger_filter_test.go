package handlers

import "testing"

func TestFilterSpecToTags_KeepsOnlyAllowedTaggedOperations(t *testing.T) {
	spec := map[string]any{
		"openapi": "3.0.3",
		"paths": map[string]any{
			"/api/v1/auth/login": map[string]any{
				"post": map[string]any{"tags": []any{"Auth"}},
			},
			"/api/v1/admin/tenants": map[string]any{
				"get":  map[string]any{"tags": []any{"Admin"}},
				"post": map[string]any{"tags": []any{"Admin"}},
			},
			"/healthz": map[string]any{
				"get": map[string]any{"tags": []any{"Health"}},
			},
		},
		"components": map[string]any{"schemas": map[string]any{"Foo": map[string]any{}}},
	}
	allowed := map[string]bool{"Auth": true, "Health": true}

	filtered := filterSpecToTags(spec, allowed)

	paths, ok := filtered["paths"].(map[string]any)
	if !ok {
		t.Fatalf("expected paths to be a map, got %T", filtered["paths"])
	}
	if _, ok := paths["/api/v1/auth/login"]; !ok {
		t.Error("expected the Auth path to survive filtering")
	}
	if _, ok := paths["/healthz"]; !ok {
		t.Error("expected the Health path to survive filtering")
	}
	if _, ok := paths["/api/v1/admin/tenants"]; ok {
		t.Error("expected the internal Admin path to be filtered out")
	}
	if len(paths) != 2 {
		t.Errorf("expected exactly 2 surviving paths, got %d", len(paths))
	}
	if _, ok := filtered["components"]; !ok {
		t.Error("expected non-paths keys like components to pass through untouched")
	}
}

func TestFilterSpecToTags_DropsOperationsWithNoTags(t *testing.T) {
	spec := map[string]any{
		"paths": map[string]any{
			"/api/v1/untagged": map[string]any{
				"get": map[string]any{},
			},
		},
	}
	filtered := filterSpecToTags(spec, map[string]bool{"Health": true})
	paths := filtered["paths"].(map[string]any)
	if len(paths) != 0 {
		t.Errorf("expected an untagged operation to be dropped, got %d paths", len(paths))
	}
}

func TestFilterSpecToTags_MultiMethodPathKeepsOnlyAllowedMethod(t *testing.T) {
	spec := map[string]any{
		"paths": map[string]any{
			"/api/v1/mixed": map[string]any{
				"get":  map[string]any{"tags": []any{"Auth"}},
				"post": map[string]any{"tags": []any{"Admin"}},
			},
		},
	}
	filtered := filterSpecToTags(spec, map[string]bool{"Auth": true})
	paths := filtered["paths"].(map[string]any)
	methods, ok := paths["/api/v1/mixed"].(map[string]any)
	if !ok {
		t.Fatalf("expected /api/v1/mixed to survive with at least one allowed method")
	}
	if _, ok := methods["get"]; !ok {
		t.Error("expected GET (Auth) to survive")
	}
	if _, ok := methods["post"]; ok {
		t.Error("expected POST (Admin, internal) to be filtered out")
	}
}

func TestIsPrivilegedForInternalDocs(t *testing.T) {
	cases := []struct {
		name string
		resp *ValidateAPIKeyResponse
		want bool
	}{
		{"nil response (anonymous / invalid secret)", nil, false},
		{"platform App secret", &ValidateAPIKeyResponse{Roles: []string{"superuser", "service"}, Service: "platform"}, true},
		{"tenant App secret", &ValidateAPIKeyResponse{Roles: []string{"service"}, Service: "tenant", Environment: "production"}, false},
		{"service-scoped plain API key", &ValidateAPIKeyResponse{Roles: []string{"superuser"}, Environment: "production"}, true},
		{"plain developer API key, no service scope", &ValidateAPIKeyResponse{Roles: []string{}, Environment: "production"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isPrivilegedForInternalDocs(tc.resp); got != tc.want {
				t.Errorf("isPrivilegedForInternalDocs(%+v) = %v, want %v", tc.resp, got, tc.want)
			}
		})
	}
}
