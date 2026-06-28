package services_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/straylight-ai/straylight/internal/services"
)

// createTempDir creates a temporary directory and registers cleanup.
func createTempDir(t *testing.T) string {
	t.Helper()
	tmpDir, err := os.MkdirTemp("", "loader-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(tmpDir) })
	return tmpDir
}

// writeFile writes content to a file in dir.
func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("failed to write %s: %v", path, err)
	}
}

// validTemplateYAML returns a syntactically and semantically valid ServiceTemplate YAML.
func validTemplateYAML(id string) string {
	return "id: " + id + `
display_name: Test Service
description: A test service
target: https://example.com
auth_methods:
  - id: bearer
    name: Bearer Token
    fields:
      - key: token
        label: Token
        type: password
        required: true
    injection:
      type: bearer_header
`
}

// ----------------------------------------------------------------
// LoadCommunityTemplates tests
// ----------------------------------------------------------------

// TestLoadCommunityTemplates_ValidYAMLLoads verifies that a valid YAML file loads correctly.
func TestLoadCommunityTemplates_ValidYAMLLoads(t *testing.T) {
	dir := createTempDir(t)
	writeFile(t, dir, "valid.yaml", validTemplateYAML("valid-service"))

	templates, errs := services.LoadCommunityTemplates(dir)

	if len(errs) != 0 {
		t.Errorf("expected no errors, got %d: %v", len(errs), errs)
	}
	if len(templates) != 1 {
		t.Fatalf("expected 1 template, got %d", len(templates))
	}
	if templates[0].ID != "valid-service" {
		t.Errorf("expected ID 'valid-service', got %q", templates[0].ID)
	}
}

// TestLoadCommunityTemplates_ValidJSONLoads verifies that a valid JSON file also loads.
func TestLoadCommunityTemplates_ValidJSONLoads(t *testing.T) {
	dir := createTempDir(t)
	writeFile(t, dir, "valid.json", `{
		"id": "json-service",
		"display_name": "JSON Service",
		"target": "https://example.com",
		"auth_methods": [{
			"id": "bearer",
			"name": "Bearer Token",
			"fields": [{"key":"token","label":"Token","type":"password","required":true}],
			"injection": {"type": "bearer_header"}
		}]
	}`)

	templates, errs := services.LoadCommunityTemplates(dir)

	if len(errs) != 0 {
		t.Errorf("expected no errors, got %v", errs)
	}
	if len(templates) != 1 || templates[0].ID != "json-service" {
		t.Errorf("expected 1 template with ID 'json-service', got %v", templates)
	}
}

// TestLoadCommunityTemplates_MalformedFileIsSkipped verifies that a malformed YAML
// file produces a per-file error and does not abort loading of other valid files.
func TestLoadCommunityTemplates_MalformedFileIsSkipped(t *testing.T) {
	dir := createTempDir(t)
	writeFile(t, dir, "malformed.yaml", "id: malformed\ndescription: [unclosed bracket\n")
	writeFile(t, dir, "valid.yaml", validTemplateYAML("valid-service"))

	templates, errs := services.LoadCommunityTemplates(dir)

	if len(errs) != 1 {
		t.Errorf("expected 1 error (for malformed file), got %d: %v", len(errs), errs)
	}
	if len(templates) != 1 {
		t.Errorf("expected 1 template (valid one), got %d", len(templates))
	}
	if len(templates) == 1 && templates[0].ID != "valid-service" {
		t.Errorf("expected 'valid-service', got %q", templates[0].ID)
	}
}

// TestLoadCommunityTemplates_InvalidTemplateIsSkipped verifies that a syntactically valid
// YAML but invalid template (e.g. no auth methods) is skipped with a per-file error.
func TestLoadCommunityTemplates_InvalidTemplateIsSkipped(t *testing.T) {
	dir := createTempDir(t)
	// Valid YAML but invalid template: no auth_methods.
	writeFile(t, dir, "no-auth.yaml", `id: no-auth-service
display_name: No Auth
target: https://example.com
auth_methods: []
`)
	writeFile(t, dir, "valid.yaml", validTemplateYAML("valid-service"))

	templates, errs := services.LoadCommunityTemplates(dir)

	if len(errs) == 0 {
		t.Error("expected at least one error for invalid template (empty auth_methods)")
	}
	if len(templates) != 1 {
		t.Errorf("expected 1 valid template, got %d", len(templates))
	}
}

// TestLoadCommunityTemplates_BadPatternNoPanic verifies that a template with an invalid
// regex Pattern in a CredentialField is skipped with an error and does NOT panic.
// This is the key difference from the compiled init() which calls MustCompile and panics.
func TestLoadCommunityTemplates_BadPatternNoPanic(t *testing.T) {
	dir := createTempDir(t)
	writeFile(t, dir, "bad-pattern.yaml", `id: bad-pattern-service
display_name: Bad Pattern
target: https://example.com
auth_methods:
  - id: bearer
    name: Bearer Token
    fields:
      - key: token
        label: Token
        type: password
        required: true
        pattern: "[invalid(regex"
    injection:
      type: bearer_header
`)
	writeFile(t, dir, "valid.yaml", validTemplateYAML("valid-service"))

	// Must not panic.
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("LoadCommunityTemplates panicked on bad regex: %v", r)
		}
	}()

	templates, errs := services.LoadCommunityTemplates(dir)

	if len(errs) == 0 {
		t.Error("expected at least one error for bad regex pattern")
	}
	// The valid template should still load.
	if len(templates) != 1 {
		t.Errorf("expected 1 valid template, got %d", len(templates))
	}
}

// TestLoadCommunityTemplates_EmptyDirReturnsNil verifies that an empty directory returns
// nil slices and no errors.
func TestLoadCommunityTemplates_EmptyDirReturnsNil(t *testing.T) {
	dir := createTempDir(t)

	templates, errs := services.LoadCommunityTemplates(dir)

	if len(templates) != 0 {
		t.Errorf("expected 0 templates, got %d", len(templates))
	}
	if len(errs) != 0 {
		t.Errorf("expected 0 errors, got %d: %v", len(errs), errs)
	}
}

// TestLoadCommunityTemplates_NonTemplateFilesIgnored verifies that non-YAML/JSON files
// are silently ignored.
func TestLoadCommunityTemplates_NonTemplateFilesIgnored(t *testing.T) {
	dir := createTempDir(t)
	writeFile(t, dir, "readme.txt", "This is a readme, not a template.")
	writeFile(t, dir, "valid.yaml", validTemplateYAML("valid-service"))

	templates, errs := services.LoadCommunityTemplates(dir)

	if len(errs) != 0 {
		t.Errorf("expected no errors, got %v", errs)
	}
	if len(templates) != 1 {
		t.Errorf("expected 1 template, got %d", len(templates))
	}
}

// ----------------------------------------------------------------
// MergeTemplates tests
// ----------------------------------------------------------------

// TestMergeTemplates_BuiltinWinsOnCollision verifies that when a community template has
// the same ID as a built-in, the built-in version is kept.
func TestMergeTemplates_BuiltinWinsOnCollision(t *testing.T) {
	builtin := []services.ServiceTemplate{
		{ID: "shared-id", DisplayName: "Builtin Service"},
		{ID: "builtin-only", DisplayName: "Builtin Only"},
	}
	community := []services.ServiceTemplate{
		{ID: "shared-id", DisplayName: "Community Service (should be ignored)"},
		{ID: "community-only", DisplayName: "Community Only"},
	}

	merged, warnings := services.MergeTemplates(builtin, community)

	if len(merged) != 3 {
		t.Errorf("expected 3 merged templates, got %d", len(merged))
	}

	var shared *services.ServiceTemplate
	for i := range merged {
		if merged[i].ID == "shared-id" {
			shared = &merged[i]
			break
		}
	}
	if shared == nil {
		t.Fatal("expected 'shared-id' in merged list")
	}
	if shared.DisplayName != "Builtin Service" {
		t.Errorf("expected builtin DisplayName 'Builtin Service', got %q", shared.DisplayName)
	}

	if len(warnings) == 0 {
		t.Error("expected at least one collision warning")
	}
}

// TestMergeTemplates_CommunityAdded verifies that a non-colliding community template is
// appended to the merged slice.
func TestMergeTemplates_CommunityAdded(t *testing.T) {
	builtin := []services.ServiceTemplate{
		{ID: "builtin-only", DisplayName: "Builtin Only"},
	}
	community := []services.ServiceTemplate{
		{ID: "community-only", DisplayName: "Community Only"},
	}

	merged, warnings := services.MergeTemplates(builtin, community)

	if len(merged) != 2 {
		t.Errorf("expected 2 templates, got %d", len(merged))
	}

	found := false
	for _, tmpl := range merged {
		if tmpl.ID == "community-only" && tmpl.DisplayName == "Community Only" {
			found = true
			break
		}
	}
	if !found {
		t.Error("community-only template not found in merged list")
	}
	if len(warnings) != 0 {
		t.Errorf("expected no warnings, got %v", warnings)
	}
}

// TestMergeTemplates_WarningContainsID verifies that a collision warning contains the
// conflicting template ID.
func TestMergeTemplates_WarningContainsID(t *testing.T) {
	builtin := []services.ServiceTemplate{
		{ID: "collision-id", DisplayName: "Builtin"},
	}
	community := []services.ServiceTemplate{
		{ID: "collision-id", DisplayName: "Community"},
	}

	_, warnings := services.MergeTemplates(builtin, community)

	if len(warnings) != 1 {
		t.Fatalf("expected 1 warning, got %d: %v", len(warnings), warnings)
	}
	if !strings.Contains(warnings[0], "collision-id") {
		t.Errorf("warning %q should contain 'collision-id'", warnings[0])
	}
}

// TestMergeTemplates_EmptyInputs verifies that merging two empty slices returns empty.
func TestMergeTemplates_EmptyInputs(t *testing.T) {
	merged, warnings := services.MergeTemplates(nil, nil)
	if len(merged) != 0 {
		t.Errorf("expected 0 templates, got %d", len(merged))
	}
	if len(warnings) != 0 {
		t.Errorf("expected 0 warnings, got %v", warnings)
	}
}
