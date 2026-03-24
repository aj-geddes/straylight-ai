package services_test

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/straylight-ai/straylight/internal/services"
)

// ---------------------------------------------------------------------------
// Mock VaultClient for testing — no real OpenBao instance needed.
// ---------------------------------------------------------------------------

type mockVault struct {
	mu      sync.RWMutex
	secrets map[string]map[string]interface{}
	// listErr and writeErr allow injecting errors for specific paths.
	listErr  map[string]error
	readErr  map[string]error
	writeErr map[string]error
	delErr   map[string]error
}

func newMockVault() *mockVault {
	return &mockVault{
		secrets:  make(map[string]map[string]interface{}),
		listErr:  make(map[string]error),
		readErr:  make(map[string]error),
		writeErr: make(map[string]error),
		delErr:   make(map[string]error),
	}
}

func (m *mockVault) WriteSecret(path string, data map[string]interface{}) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err, ok := m.writeErr[path]; ok {
		return err
	}
	clone := make(map[string]interface{}, len(data))
	for k, v := range data {
		clone[k] = v
	}
	m.secrets[path] = clone
	return nil
}

func (m *mockVault) ReadSecret(path string) (map[string]interface{}, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if err, ok := m.readErr[path]; ok {
		return nil, err
	}
	data, ok := m.secrets[path]
	if !ok {
		return nil, errors.New("secret not found: " + path)
	}
	clone := make(map[string]interface{}, len(data))
	for k, v := range data {
		clone[k] = v
	}
	return clone, nil
}

func (m *mockVault) DeleteSecret(path string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err, ok := m.delErr[path]; ok {
		return err
	}
	delete(m.secrets, path)
	return nil
}

func (m *mockVault) ListSecrets(path string) ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if err, ok := m.listErr[path]; ok {
		return nil, err
	}
	// Return the unique top-level path components that are children of path.
	// e.g. for path="services/" and secrets {"services/github/metadata": ...}
	// return ["github"].
	seen := make(map[string]bool)
	var keys []string
	for k := range m.secrets {
		if len(k) <= len(path) {
			continue
		}
		if k[:len(path)] != path {
			continue
		}
		rest := k[len(path):]
		// Take the first path component.
		idx := 0
		for idx < len(rest) && rest[idx] != '/' {
			idx++
		}
		component := rest[:idx]
		if component != "" && !seen[component] {
			seen[component] = true
			keys = append(keys, component)
		}
	}
	return keys, nil
}

// hasSecret reports whether the mock vault has a secret at path.
func (m *mockVault) hasSecret(path string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.secrets[path]
	return ok
}

// ---------------------------------------------------------------------------
// Registry.Create tests
// ---------------------------------------------------------------------------

func TestRegistry_Create_StoresServiceAndCredential(t *testing.T) {
	vault := newMockVault()
	reg := services.NewRegistry(vault)

	svc := services.Service{
		Name:   "stripe",
		Type:   "http_proxy",
		Target: "https://api.stripe.com",
		Inject: "header",
	}
	err := reg.Create(svc, "sk_test_abc123")
	if err != nil {
		t.Fatalf("Create() returned unexpected error: %v", err)
	}

	// Service should be retrievable.
	got, err := reg.Get("stripe")
	if err != nil {
		t.Fatalf("Get() returned unexpected error after Create: %v", err)
	}
	if got.Name != "stripe" {
		t.Errorf("expected name=stripe, got %q", got.Name)
	}
	if got.Type != "http_proxy" {
		t.Errorf("expected type=http_proxy, got %q", got.Type)
	}
	if got.Target != "https://api.stripe.com" {
		t.Errorf("expected target=https://api.stripe.com, got %q", got.Target)
	}

	// Credential must be in vault.
	if !vault.hasSecret("services/stripe/credential") {
		t.Error("expected credential to be stored in vault at services/stripe/credential")
	}
}

func TestRegistry_Create_SetsCreatedAtAndUpdatedAt(t *testing.T) {
	vault := newMockVault()
	reg := services.NewRegistry(vault)

	before := time.Now()
	svc := services.Service{
		Name:   "openai",
		Type:   "http_proxy",
		Target: "https://api.openai.com",
		Inject: "header",
	}
	if err := reg.Create(svc, "sk-abc"); err != nil {
		t.Fatalf("Create() returned unexpected error: %v", err)
	}
	after := time.Now()

	got, _ := reg.Get("openai")
	if got.CreatedAt.Before(before) || got.CreatedAt.After(after) {
		t.Errorf("expected CreatedAt between %v and %v, got %v", before, after, got.CreatedAt)
	}
	if got.UpdatedAt.Before(before) || got.UpdatedAt.After(after) {
		t.Errorf("expected UpdatedAt between %v and %v, got %v", before, after, got.UpdatedAt)
	}
}

func TestRegistry_Create_SetsStatusAvailable(t *testing.T) {
	vault := newMockVault()
	reg := services.NewRegistry(vault)

	svc := services.Service{
		Name:   "github",
		Type:   "http_proxy",
		Target: "https://api.github.com",
		Inject: "header",
	}
	if err := reg.Create(svc, "ghp_token"); err != nil {
		t.Fatalf("Create() returned unexpected error: %v", err)
	}

	got, _ := reg.Get("github")
	if got.Status != "available" {
		t.Errorf("expected status=available, got %q", got.Status)
	}
}

func TestRegistry_Create_DuplicateName_ReturnsError(t *testing.T) {
	vault := newMockVault()
	reg := services.NewRegistry(vault)

	svc := services.Service{
		Name:   "stripe",
		Type:   "http_proxy",
		Target: "https://api.stripe.com",
		Inject: "header",
	}
	if err := reg.Create(svc, "key1"); err != nil {
		t.Fatalf("first Create() returned unexpected error: %v", err)
	}

	err := reg.Create(svc, "key2")
	if err == nil {
		t.Fatal("expected error for duplicate service name, got nil")
	}
}

func TestRegistry_Create_VaultWriteError_ReturnsError(t *testing.T) {
	vault := newMockVault()
	vault.writeErr["services/failsvc/credential"] = errors.New("vault write failed")
	reg := services.NewRegistry(vault)

	svc := services.Service{
		Name:   "failsvc",
		Type:   "http_proxy",
		Target: "https://example.com",
		Inject: "header",
	}
	err := reg.Create(svc, "some-key")
	if err == nil {
		t.Fatal("expected error when vault write fails, got nil")
	}

	// Service must NOT be left in registry if vault write failed.
	_, getErr := reg.Get("failsvc")
	if getErr == nil {
		t.Error("expected Get() to fail for service whose Create() failed, but it succeeded")
	}
}

// ---------------------------------------------------------------------------
// Registry.Get tests
// ---------------------------------------------------------------------------

func TestRegistry_Get_NotFound_ReturnsError(t *testing.T) {
	vault := newMockVault()
	reg := services.NewRegistry(vault)

	_, err := reg.Get("nonexistent")
	if err == nil {
		t.Fatal("expected error for non-existent service, got nil")
	}
}

func TestRegistry_Get_NeverReturnsCredential(t *testing.T) {
	// Credential fields must never appear in Get() or List() results.
	// The Service struct has no Credential field by design; this test verifies
	// that no credential-containing field is sneaked into the returned Service.
	vault := newMockVault()
	reg := services.NewRegistry(vault)

	svc := services.Service{
		Name:   "stripe",
		Type:   "http_proxy",
		Target: "https://api.stripe.com",
		Inject: "header",
	}
	if err := reg.Create(svc, "sk_live_SECRET"); err != nil {
		t.Fatalf("Create() returned unexpected error: %v", err)
	}

	got, err := reg.Get("stripe")
	if err != nil {
		t.Fatalf("Get() returned unexpected error: %v", err)
	}

	// The returned Service struct must not contain the credential.
	// We verify by ensuring HeaderTemplate and similar fields do NOT contain the secret.
	if got.HeaderTemplate == "sk_live_SECRET" {
		t.Error("Get() returned credential in HeaderTemplate — credential leaked!")
	}
	if got.Target == "sk_live_SECRET" {
		t.Error("Get() returned credential in Target — credential leaked!")
	}
}

// ---------------------------------------------------------------------------
// Registry.List tests
// ---------------------------------------------------------------------------

func TestRegistry_List_ReturnsAllServices(t *testing.T) {
	vault := newMockVault()
	reg := services.NewRegistry(vault)

	names := []string{"stripe", "github", "openai"}
	for _, name := range names {
		svc := services.Service{
			Name:   name,
			Type:   "http_proxy",
			Target: "https://example.com/" + name,
			Inject: "header",
		}
		if err := reg.Create(svc, "cred-"+name); err != nil {
			t.Fatalf("Create(%q) returned unexpected error: %v", name, err)
		}
	}

	list := reg.List()
	if len(list) != len(names) {
		t.Errorf("expected %d services, got %d", len(names), len(list))
	}
}

func TestRegistry_List_EmptyRegistry_ReturnsEmptySlice(t *testing.T) {
	vault := newMockVault()
	reg := services.NewRegistry(vault)

	list := reg.List()
	if list == nil {
		t.Error("expected empty slice (not nil) from List() on empty registry")
	}
	if len(list) != 0 {
		t.Errorf("expected 0 services, got %d", len(list))
	}
}

// ---------------------------------------------------------------------------
// Registry.Update tests
// ---------------------------------------------------------------------------

func TestRegistry_Update_ChangesServiceFields(t *testing.T) {
	vault := newMockVault()
	reg := services.NewRegistry(vault)

	svc := services.Service{
		Name:   "stripe",
		Type:   "http_proxy",
		Target: "https://api.stripe.com",
		Inject: "header",
	}
	if err := reg.Create(svc, "old-key"); err != nil {
		t.Fatalf("Create() returned unexpected error: %v", err)
	}

	updated := services.Service{
		Name:   "stripe",
		Type:   "http_proxy",
		Target: "https://api.stripe.com/v2",
		Inject: "query",
	}
	if err := reg.Update("stripe", updated, nil); err != nil {
		t.Fatalf("Update() returned unexpected error: %v", err)
	}

	got, _ := reg.Get("stripe")
	if got.Target != "https://api.stripe.com/v2" {
		t.Errorf("expected updated target, got %q", got.Target)
	}
	if got.Inject != "query" {
		t.Errorf("expected updated inject=query, got %q", got.Inject)
	}
}

func TestRegistry_Update_WithCredential_UpdatesVault(t *testing.T) {
	vault := newMockVault()
	reg := services.NewRegistry(vault)

	svc := services.Service{
		Name:   "stripe",
		Type:   "http_proxy",
		Target: "https://api.stripe.com",
		Inject: "header",
	}
	if err := reg.Create(svc, "old-key"); err != nil {
		t.Fatalf("Create() returned unexpected error: %v", err)
	}

	newCred := "new-key"
	if err := reg.Update("stripe", svc, &newCred); err != nil {
		t.Fatalf("Update() with credential returned unexpected error: %v", err)
	}

	// New credential should be stored in vault.
	cred, err := reg.GetCredential("stripe")
	if err != nil {
		t.Fatalf("GetCredential() returned unexpected error: %v", err)
	}
	if cred != "new-key" {
		t.Errorf("expected credential=new-key after update, got %q", cred)
	}
}

func TestRegistry_Update_WithoutCredential_PreservesExistingCredential(t *testing.T) {
	vault := newMockVault()
	reg := services.NewRegistry(vault)

	svc := services.Service{
		Name:   "stripe",
		Type:   "http_proxy",
		Target: "https://api.stripe.com",
		Inject: "header",
	}
	if err := reg.Create(svc, "original-key"); err != nil {
		t.Fatalf("Create() returned unexpected error: %v", err)
	}

	updated := services.Service{
		Name:   "stripe",
		Type:   "http_proxy",
		Target: "https://api.stripe.com/v3",
		Inject: "header",
	}
	if err := reg.Update("stripe", updated, nil); err != nil {
		t.Fatalf("Update() returned unexpected error: %v", err)
	}

	cred, err := reg.GetCredential("stripe")
	if err != nil {
		t.Fatalf("GetCredential() returned unexpected error: %v", err)
	}
	if cred != "original-key" {
		t.Errorf("expected credential=original-key preserved, got %q", cred)
	}
}

func TestRegistry_Update_UpdatesUpdatedAt(t *testing.T) {
	vault := newMockVault()
	reg := services.NewRegistry(vault)

	svc := services.Service{
		Name:   "stripe",
		Type:   "http_proxy",
		Target: "https://api.stripe.com",
		Inject: "header",
	}
	if err := reg.Create(svc, "key"); err != nil {
		t.Fatalf("Create() returned unexpected error: %v", err)
	}

	original, _ := reg.Get("stripe")
	// Sleep briefly so UpdatedAt changes.
	time.Sleep(2 * time.Millisecond)

	before := time.Now()
	if err := reg.Update("stripe", svc, nil); err != nil {
		t.Fatalf("Update() returned unexpected error: %v", err)
	}
	after := time.Now()

	got, _ := reg.Get("stripe")
	if !got.UpdatedAt.After(original.UpdatedAt) {
		t.Error("expected UpdatedAt to increase after Update()")
	}
	if got.UpdatedAt.Before(before) || got.UpdatedAt.After(after) {
		t.Errorf("UpdatedAt %v outside expected range [%v, %v]", got.UpdatedAt, before, after)
	}
	// CreatedAt must not change.
	if !got.CreatedAt.Equal(original.CreatedAt) {
		t.Error("CreatedAt must not change during Update()")
	}
}

func TestRegistry_Update_NotFound_ReturnsError(t *testing.T) {
	vault := newMockVault()
	reg := services.NewRegistry(vault)

	svc := services.Service{Name: "ghost", Type: "http_proxy", Target: "https://example.com", Inject: "header"}
	err := reg.Update("ghost", svc, nil)
	if err == nil {
		t.Fatal("expected error when updating non-existent service, got nil")
	}
}

// ---------------------------------------------------------------------------
// Registry.Delete tests
// ---------------------------------------------------------------------------

func TestRegistry_Delete_RemovesServiceAndCredential(t *testing.T) {
	vault := newMockVault()
	reg := services.NewRegistry(vault)

	svc := services.Service{
		Name:   "stripe",
		Type:   "http_proxy",
		Target: "https://api.stripe.com",
		Inject: "header",
	}
	if err := reg.Create(svc, "sk_test_abc"); err != nil {
		t.Fatalf("Create() returned unexpected error: %v", err)
	}

	if err := reg.Delete("stripe"); err != nil {
		t.Fatalf("Delete() returned unexpected error: %v", err)
	}

	// Service must no longer exist.
	_, err := reg.Get("stripe")
	if err == nil {
		t.Error("expected Get() to fail after Delete(), but it succeeded")
	}

	// Credential must be deleted from vault (no orphans).
	if vault.hasSecret("services/stripe/credential") {
		t.Error("credential still in vault after service deletion — orphaned secret!")
	}
}

func TestRegistry_Delete_NotFound_ReturnsError(t *testing.T) {
	vault := newMockVault()
	reg := services.NewRegistry(vault)

	err := reg.Delete("nonexistent")
	if err == nil {
		t.Fatal("expected error when deleting non-existent service, got nil")
	}
}

// ---------------------------------------------------------------------------
// Registry.CheckCredential tests
// ---------------------------------------------------------------------------

func TestRegistry_CheckCredential_Available(t *testing.T) {
	vault := newMockVault()
	reg := services.NewRegistry(vault)

	svc := services.Service{
		Name:   "stripe",
		Type:   "http_proxy",
		Target: "https://api.stripe.com",
		Inject: "header",
	}
	if err := reg.Create(svc, "sk_test_abc"); err != nil {
		t.Fatalf("Create() returned unexpected error: %v", err)
	}

	status, err := reg.CheckCredential("stripe")
	if err != nil {
		t.Fatalf("CheckCredential() returned unexpected error: %v", err)
	}
	if status != "available" {
		t.Errorf("expected status=available, got %q", status)
	}
}

func TestRegistry_CheckCredential_NotConfigured_WhenVaultMissing(t *testing.T) {
	vault := newMockVault()
	reg := services.NewRegistry(vault)

	// Create service but inject a vault read error to simulate missing credential.
	svc := services.Service{
		Name:   "stripe",
		Type:   "http_proxy",
		Target: "https://api.stripe.com",
		Inject: "header",
	}
	if err := reg.Create(svc, "sk_test_abc"); err != nil {
		t.Fatalf("Create() returned unexpected error: %v", err)
	}

	// Remove the credential directly from the vault mock.
	vault.mu.Lock()
	delete(vault.secrets, "services/stripe/credential")
	vault.mu.Unlock()

	status, err := reg.CheckCredential("stripe")
	if err != nil {
		t.Fatalf("CheckCredential() returned unexpected error: %v", err)
	}
	if status != "not_configured" {
		t.Errorf("expected status=not_configured when vault secret missing, got %q", status)
	}
}

func TestRegistry_CheckCredential_ServiceNotFound_ReturnsError(t *testing.T) {
	vault := newMockVault()
	reg := services.NewRegistry(vault)

	_, err := reg.CheckCredential("nonexistent")
	if err == nil {
		t.Fatal("expected error for non-existent service, got nil")
	}
}

// ---------------------------------------------------------------------------
// Registry.GetCredential tests
// ---------------------------------------------------------------------------

func TestRegistry_GetCredential_ReturnsStoredCredential(t *testing.T) {
	vault := newMockVault()
	reg := services.NewRegistry(vault)

	svc := services.Service{
		Name:   "openai",
		Type:   "http_proxy",
		Target: "https://api.openai.com",
		Inject: "header",
	}
	if err := reg.Create(svc, "sk-secret-key"); err != nil {
		t.Fatalf("Create() returned unexpected error: %v", err)
	}

	cred, err := reg.GetCredential("openai")
	if err != nil {
		t.Fatalf("GetCredential() returned unexpected error: %v", err)
	}
	if cred != "sk-secret-key" {
		t.Errorf("expected credential=sk-secret-key, got %q", cred)
	}
}

func TestRegistry_GetCredential_ServiceNotFound_ReturnsError(t *testing.T) {
	vault := newMockVault()
	reg := services.NewRegistry(vault)

	_, err := reg.GetCredential("nonexistent")
	if err == nil {
		t.Fatal("expected error for non-existent service, got nil")
	}
}

// ---------------------------------------------------------------------------
// Thread-safety test
// ---------------------------------------------------------------------------

func TestRegistry_ConcurrentCreateAndList_NoRace(t *testing.T) {
	vault := newMockVault()
	reg := services.NewRegistry(vault)

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			name := "svc" + string(rune('a'+i))
			svc := services.Service{
				Name:   name,
				Type:   "http_proxy",
				Target: "https://example.com/" + name,
				Inject: "header",
			}
			// Ignore duplicate errors — some goroutines may collide on the same name.
			_ = reg.Create(svc, "cred-"+name)
			_ = reg.List()
		}(i)
	}
	wg.Wait()
}

// ---------------------------------------------------------------------------
// Validation tests
// ---------------------------------------------------------------------------

func TestRegistry_Create_InvalidName_ReturnsError(t *testing.T) {
	cases := []struct {
		name string
		desc string
	}{
		{"", "empty name"},
		{"UPPERCASE", "uppercase letters"},
		{"has space", "contains space"},
		{"has/slash", "contains slash"},
		{"1startsdigit", "starts with digit"},
		{"a" + "bcdefghijklmnopqrstuvwxyz01234567890abcdefghijklmnopqrstuvwxyz0", "name too long (65 chars)"},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			vault := newMockVault()
			reg := services.NewRegistry(vault)

			svc := services.Service{
				Name:   tc.name,
				Type:   "http_proxy",
				Target: "https://example.com",
				Inject: "header",
			}
			err := reg.Create(svc, "cred")
			if err == nil {
				t.Errorf("Create(%q) expected validation error for %s, got nil", tc.name, tc.desc)
			}
		})
	}
}

func TestRegistry_Create_ValidNames_Accepted(t *testing.T) {
	cases := []string{
		"a",
		"stripe",
		"my-service",
		"my-service-123",
		"abc123",
		"a" + "bcdefghijklmnopqrstuvwxyz01234567890abcdefghijklmnopqrstuvwxy", // 63 chars total
	}

	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			vault := newMockVault()
			reg := services.NewRegistry(vault)

			svc := services.Service{
				Name:   name,
				Type:   "http_proxy",
				Target: "https://example.com",
				Inject: "header",
			}
			err := reg.Create(svc, "cred")
			if err != nil {
				t.Errorf("Create(%q) expected valid name to be accepted, got error: %v", name, err)
			}
		})
	}
}

func TestRegistry_Create_InvalidType_ReturnsError(t *testing.T) {
	vault := newMockVault()
	reg := services.NewRegistry(vault)

	svc := services.Service{
		Name:   "mysvc",
		Type:   "invalid_type",
		Target: "https://example.com",
		Inject: "header",
	}
	err := reg.Create(svc, "cred")
	if err == nil {
		t.Fatal("expected validation error for invalid type, got nil")
	}
}

func TestRegistry_Create_InvalidTarget_ReturnsError(t *testing.T) {
	cases := []struct {
		target string
		desc   string
	}{
		{"", "empty target"},
		{"not-a-url", "not a URL"},
		{"http://api.example.com", "http scheme (not https)"},
		{"ftp://files.example.com", "ftp scheme"},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			vault := newMockVault()
			reg := services.NewRegistry(vault)

			svc := services.Service{
				Name:   "mysvc",
				Type:   "http_proxy",
				Target: tc.target,
				Inject: "header",
			}
			err := reg.Create(svc, "cred")
			if err == nil {
				t.Errorf("Create(target=%q) expected validation error for %s, got nil", tc.target, tc.desc)
			}
		})
	}
}

func TestRegistry_Create_InvalidInject_ReturnsError(t *testing.T) {
	vault := newMockVault()
	reg := services.NewRegistry(vault)

	svc := services.Service{
		Name:   "mysvc",
		Type:   "http_proxy",
		Target: "https://example.com",
		Inject: "body", // only "header" and "query" are supported per the spec
	}
	err := reg.Create(svc, "cred")
	if err == nil {
		t.Fatal("expected validation error for inject=body, got nil")
	}
}

func TestRegistry_Create_ValidHTTPS_Accepted(t *testing.T) {
	vault := newMockVault()
	reg := services.NewRegistry(vault)

	svc := services.Service{
		Name:   "mysvc",
		Type:   "http_proxy",
		Target: "https://api.example.com",
		Inject: "header",
	}
	err := reg.Create(svc, "cred")
	if err != nil {
		t.Errorf("Create() with valid https target returned unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Registry.WriteCredentials / ReadCredentials tests (WP-MA-2)
// ---------------------------------------------------------------------------

func TestRegistry_WriteCredentials_StoresMultiFieldCredential(t *testing.T) {
	v := newMockVault()
	reg := services.NewRegistry(v)

	svc := services.Service{
		Name:   "aws",
		Type:   "http_proxy",
		Target: "https://s3.amazonaws.com",
		Inject: "header",
	}
	if err := reg.CreateWithAuth(svc, "access-key", map[string]string{
		"access_key_id":     "AKIAIOSFODNN7EXAMPLE",
		"secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	}); err != nil {
		t.Fatalf("CreateWithAuth() returned unexpected error: %v", err)
	}

	// Vault secret must contain auth_method + both fields.
	secret, ok := v.secrets["services/aws/credential"]
	if !ok {
		t.Fatal("expected vault secret at services/aws/credential, not found")
	}
	if secret["auth_method"] != "access-key" {
		t.Errorf("expected auth_method=access-key, got %v", secret["auth_method"])
	}
	if secret["access_key_id"] != "AKIAIOSFODNN7EXAMPLE" {
		t.Errorf("expected access_key_id=AKIAIOSFODNN7EXAMPLE, got %v", secret["access_key_id"])
	}
	if secret["secret_access_key"] != "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" {
		t.Errorf("expected secret_access_key in vault, got %v", secret["secret_access_key"])
	}
}

func TestRegistry_ReadCredentials_ReadsNewFormat(t *testing.T) {
	v := newMockVault()
	reg := services.NewRegistry(v)

	svc := services.Service{
		Name:   "aws",
		Type:   "http_proxy",
		Target: "https://s3.amazonaws.com",
		Inject: "header",
	}
	if err := reg.CreateWithAuth(svc, "access-key", map[string]string{
		"access_key_id":     "AKIAIOSFODNN7EXAMPLE",
		"secret_access_key": "wJalrXUtnFEMI/K7MDENG",
	}); err != nil {
		t.Fatalf("CreateWithAuth() returned unexpected error: %v", err)
	}

	authMethod, fields, err := reg.ReadCredentials("aws")
	if err != nil {
		t.Fatalf("ReadCredentials() returned unexpected error: %v", err)
	}
	if authMethod != "access-key" {
		t.Errorf("expected authMethod=access-key, got %q", authMethod)
	}
	if fields["access_key_id"] != "AKIAIOSFODNN7EXAMPLE" {
		t.Errorf("expected access_key_id=AKIAIOSFODNN7EXAMPLE, got %q", fields["access_key_id"])
	}
	if fields["secret_access_key"] != "wJalrXUtnFEMI/K7MDENG" {
		t.Errorf("expected secret_access_key in fields, got %q", fields["secret_access_key"])
	}
	// auth_method must NOT appear in the returned fields map.
	if _, present := fields["auth_method"]; present {
		t.Error("auth_method must not appear in the returned fields map")
	}
}

func TestRegistry_ReadCredentials_ReadsLegacyFormat(t *testing.T) {
	v := newMockVault()
	reg := services.NewRegistry(v)

	// Inject a legacy-format secret directly into the vault (no auth_method key).
	v.secrets["services/github/credential"] = map[string]interface{}{
		"value": "ghp_legacytoken",
		"type":  "api_key",
	}
	// Also create the service metadata so ReadCredentials can look it up.
	svc := services.Service{
		Name:   "github",
		Type:   "http_proxy",
		Target: "https://api.github.com",
		Inject: "header",
	}
	// Bypass Create (which would overwrite the vault secret) by storing via CreateWithAuth
	// using a temporary secret, then restoring the legacy secret.
	if err := reg.CreateWithAuth(svc, "pat", map[string]string{"token": "temp"}); err != nil {
		t.Fatalf("setup CreateWithAuth() returned unexpected error: %v", err)
	}
	// Overwrite with legacy format.
	v.mu.Lock()
	v.secrets["services/github/credential"] = map[string]interface{}{
		"value": "ghp_legacytoken",
		"type":  "api_key",
	}
	v.mu.Unlock()

	authMethod, fields, err := reg.ReadCredentials("github")
	if err != nil {
		t.Fatalf("ReadCredentials() returned unexpected error for legacy format: %v", err)
	}
	if authMethod != "legacy" {
		t.Errorf("expected authMethod=legacy for legacy format, got %q", authMethod)
	}
	if fields["value"] != "ghp_legacytoken" {
		t.Errorf("expected fields[value]=ghp_legacytoken, got %q", fields["value"])
	}
}

func TestRegistry_ReadCredentials_ServiceNotFound_ReturnsError(t *testing.T) {
	v := newMockVault()
	reg := services.NewRegistry(v)

	_, _, err := reg.ReadCredentials("nonexistent")
	if err == nil {
		t.Fatal("expected error for non-existent service, got nil")
	}
}

func TestRegistry_ReadCredentials_VaultError_ReturnsError(t *testing.T) {
	v := newMockVault()
	reg := services.NewRegistry(v)

	svc := services.Service{
		Name:   "aws",
		Type:   "http_proxy",
		Target: "https://s3.amazonaws.com",
		Inject: "header",
	}
	if err := reg.CreateWithAuth(svc, "access-key", map[string]string{"access_key_id": "AKI"}); err != nil {
		t.Fatalf("CreateWithAuth() returned unexpected error: %v", err)
	}

	v.readErr["services/aws/credential"] = errors.New("vault unavailable")

	_, _, err := reg.ReadCredentials("aws")
	if err == nil {
		t.Fatal("expected error when vault read fails, got nil")
	}
}

func TestRegistry_ReadCredentials_UnrecognizedFormat_ReturnsError(t *testing.T) {
	v := newMockVault()
	reg := services.NewRegistry(v)

	svc := services.Service{
		Name:   "weird",
		Type:   "http_proxy",
		Target: "https://example.com",
		Inject: "header",
	}
	if err := reg.CreateWithAuth(svc, "custom", map[string]string{"token": "abc"}); err != nil {
		t.Fatalf("CreateWithAuth() returned unexpected error: %v", err)
	}
	// Overwrite vault secret with a format that has neither auth_method nor value.
	v.mu.Lock()
	v.secrets["services/weird/credential"] = map[string]interface{}{
		"something_else": "xyz",
	}
	v.mu.Unlock()

	_, _, err := reg.ReadCredentials("weird")
	if err == nil {
		t.Fatal("expected error for unrecognized credential format, got nil")
	}
}

// ---------------------------------------------------------------------------
// Registry.GetCredential backward compatibility tests (WP-MA-2)
// ---------------------------------------------------------------------------

func TestRegistry_GetCredential_BackwardCompat_ViaNewFormat(t *testing.T) {
	// GetCredential must still work when credentials are stored in the new
	// multi-field format. It should return the first non-auth_method field value.
	v := newMockVault()
	reg := services.NewRegistry(v)

	svc := services.Service{
		Name:   "github",
		Type:   "http_proxy",
		Target: "https://api.github.com",
		Inject: "header",
	}
	if err := reg.CreateWithAuth(svc, "pat", map[string]string{"token": "ghp_mytoken"}); err != nil {
		t.Fatalf("CreateWithAuth() returned unexpected error: %v", err)
	}

	cred, err := reg.GetCredential("github")
	if err != nil {
		t.Fatalf("GetCredential() returned unexpected error: %v", err)
	}
	if cred == "" {
		t.Error("GetCredential() returned empty string for new-format credential")
	}
}

func TestRegistry_GetCredential_BackwardCompat_ViaLegacyFormat(t *testing.T) {
	// GetCredential must return the "value" field for legacy-format secrets.
	v := newMockVault()
	reg := services.NewRegistry(v)

	svc := services.Service{
		Name:   "stripe",
		Type:   "http_proxy",
		Target: "https://api.stripe.com",
		Inject: "header",
	}
	// Use legacy Create to store a legacy-format credential.
	if err := reg.Create(svc, "sk_legacy_abc"); err != nil {
		t.Fatalf("Create() returned unexpected error: %v", err)
	}

	cred, err := reg.GetCredential("stripe")
	if err != nil {
		t.Fatalf("GetCredential() returned unexpected error: %v", err)
	}
	if cred != "sk_legacy_abc" {
		t.Errorf("GetCredential() expected sk_legacy_abc, got %q", cred)
	}
}

// ---------------------------------------------------------------------------
// Registry.CreateWithAuth tests (WP-MA-2)
// ---------------------------------------------------------------------------

func TestRegistry_CreateWithAuth_SetsAuthMethodID(t *testing.T) {
	v := newMockVault()
	reg := services.NewRegistry(v)

	svc := services.Service{
		Name:   "aws",
		Type:   "http_proxy",
		Target: "https://s3.amazonaws.com",
		Inject: "header",
	}
	if err := reg.CreateWithAuth(svc, "access-key", map[string]string{
		"access_key_id":     "AKIA1",
		"secret_access_key": "secret1",
	}); err != nil {
		t.Fatalf("CreateWithAuth() returned unexpected error: %v", err)
	}

	got, err := reg.Get("aws")
	if err != nil {
		t.Fatalf("Get() returned unexpected error: %v", err)
	}
	if got.AuthMethodID != "access-key" {
		t.Errorf("expected AuthMethodID=access-key, got %q", got.AuthMethodID)
	}
}

func TestRegistry_CreateWithAuth_DuplicateName_ReturnsError(t *testing.T) {
	v := newMockVault()
	reg := services.NewRegistry(v)

	svc := services.Service{
		Name:   "aws",
		Type:   "http_proxy",
		Target: "https://s3.amazonaws.com",
		Inject: "header",
	}
	creds := map[string]string{"access_key_id": "AKIA1", "secret_access_key": "sec1"}
	if err := reg.CreateWithAuth(svc, "access-key", creds); err != nil {
		t.Fatalf("first CreateWithAuth() returned unexpected error: %v", err)
	}

	err := reg.CreateWithAuth(svc, "access-key", creds)
	if err == nil {
		t.Fatal("expected error for duplicate service name, got nil")
	}
}

func TestRegistry_CreateWithAuth_VaultWriteError_ServiceNotStored(t *testing.T) {
	v := newMockVault()
	v.writeErr["services/failsvc/credential"] = errors.New("vault write failed")
	reg := services.NewRegistry(v)

	svc := services.Service{
		Name:   "failsvc",
		Type:   "http_proxy",
		Target: "https://example.com",
		Inject: "header",
	}
	err := reg.CreateWithAuth(svc, "pat", map[string]string{"token": "abc"})
	if err == nil {
		t.Fatal("expected error when vault write fails, got nil")
	}

	_, getErr := reg.Get("failsvc")
	if getErr == nil {
		t.Error("service must not be stored when vault write fails")
	}
}

func TestRegistry_CreateWithAuth_SetsTimestampsAndStatus(t *testing.T) {
	v := newMockVault()
	reg := services.NewRegistry(v)

	before := time.Now()
	svc := services.Service{
		Name:   "github",
		Type:   "http_proxy",
		Target: "https://api.github.com",
		Inject: "header",
	}
	if err := reg.CreateWithAuth(svc, "pat", map[string]string{"token": "ghp_x"}); err != nil {
		t.Fatalf("CreateWithAuth() returned unexpected error: %v", err)
	}
	after := time.Now()

	got, _ := reg.Get("github")
	if got.CreatedAt.Before(before) || got.CreatedAt.After(after) {
		t.Errorf("CreatedAt %v outside expected range", got.CreatedAt)
	}
	if got.Status != "available" {
		t.Errorf("expected status=available, got %q", got.Status)
	}
}

// ---------------------------------------------------------------------------
// Registry.UpdateCredentials tests (WP-MA-2)
// ---------------------------------------------------------------------------

func TestRegistry_UpdateCredentials_ReplacesAllFieldsAtomically(t *testing.T) {
	v := newMockVault()
	reg := services.NewRegistry(v)

	svc := services.Service{
		Name:   "aws",
		Type:   "http_proxy",
		Target: "https://s3.amazonaws.com",
		Inject: "header",
	}
	if err := reg.CreateWithAuth(svc, "access-key", map[string]string{
		"access_key_id":     "AKIA_OLD",
		"secret_access_key": "secret_OLD",
	}); err != nil {
		t.Fatalf("CreateWithAuth() returned unexpected error: %v", err)
	}

	if err := reg.UpdateCredentials("aws", "access-key", map[string]string{
		"access_key_id":     "AKIA_NEW",
		"secret_access_key": "secret_NEW",
	}); err != nil {
		t.Fatalf("UpdateCredentials() returned unexpected error: %v", err)
	}

	authMethod, fields, err := reg.ReadCredentials("aws")
	if err != nil {
		t.Fatalf("ReadCredentials() after UpdateCredentials() returned unexpected error: %v", err)
	}
	if authMethod != "access-key" {
		t.Errorf("expected authMethod=access-key after update, got %q", authMethod)
	}
	if fields["access_key_id"] != "AKIA_NEW" {
		t.Errorf("expected access_key_id=AKIA_NEW after update, got %q", fields["access_key_id"])
	}
	if fields["secret_access_key"] != "secret_NEW" {
		t.Errorf("expected secret_access_key=secret_NEW after update, got %q", fields["secret_access_key"])
	}
}

func TestRegistry_UpdateCredentials_ServiceNotFound_ReturnsError(t *testing.T) {
	v := newMockVault()
	reg := services.NewRegistry(v)

	err := reg.UpdateCredentials("nonexistent", "pat", map[string]string{"token": "abc"})
	if err == nil {
		t.Fatal("expected error for non-existent service, got nil")
	}
}

func TestRegistry_UpdateCredentials_VaultError_ReturnsError(t *testing.T) {
	v := newMockVault()
	reg := services.NewRegistry(v)

	svc := services.Service{
		Name:   "github",
		Type:   "http_proxy",
		Target: "https://api.github.com",
		Inject: "header",
	}
	if err := reg.CreateWithAuth(svc, "pat", map[string]string{"token": "ghp_old"}); err != nil {
		t.Fatalf("CreateWithAuth() returned unexpected error: %v", err)
	}

	v.writeErr["services/github/credential"] = errors.New("vault write failed")

	err := reg.UpdateCredentials("github", "pat", map[string]string{"token": "ghp_new"})
	if err == nil {
		t.Fatal("expected error when vault write fails, got nil")
	}
}

// ---------------------------------------------------------------------------
// Legacy Create stores in new format with auth_method="api_key" (WP-MA-2)
// ---------------------------------------------------------------------------

func TestRegistry_LegacyCreate_StoresWithAuthMethodAPIKey(t *testing.T) {
	// The legacy Create() method must now store credentials with auth_method="api_key"
	// so that ReadCredentials can detect them as new-format secrets.
	v := newMockVault()
	reg := services.NewRegistry(v)

	svc := services.Service{
		Name:   "stripe",
		Type:   "http_proxy",
		Target: "https://api.stripe.com",
		Inject: "header",
	}
	if err := reg.Create(svc, "sk_test_abc"); err != nil {
		t.Fatalf("Create() returned unexpected error: %v", err)
	}

	secret := v.secrets["services/stripe/credential"]
	if secret["auth_method"] != "api_key" {
		t.Errorf("expected legacy Create to store auth_method=api_key, got %v", secret["auth_method"])
	}
	if secret["value"] != "sk_test_abc" {
		t.Errorf("expected value=sk_test_abc in vault, got %v", secret["value"])
	}
}

// ---------------------------------------------------------------------------
// Additional GetCredential coverage tests (WP-MA-2)
// ---------------------------------------------------------------------------

func TestRegistry_GetCredential_FallsBackToFirstFieldWhenNoTokenOrValue(t *testing.T) {
	// When auth_method is set but neither "token" nor "value" key exists,
	// GetCredential should return the first available string field.
	v := newMockVault()
	reg := services.NewRegistry(v)

	svc := services.Service{
		Name:   "aws",
		Type:   "http_proxy",
		Target: "https://s3.amazonaws.com",
		Inject: "header",
	}
	if err := reg.CreateWithAuth(svc, "access-key", map[string]string{
		"access_key_id":     "AKIAIOSFODNN7EXAMPLE",
		"secret_access_key": "wJalrXUtnFEMI",
	}); err != nil {
		t.Fatalf("CreateWithAuth() returned unexpected error: %v", err)
	}

	cred, err := reg.GetCredential("aws")
	if err != nil {
		t.Fatalf("GetCredential() returned unexpected error: %v", err)
	}
	if cred == "" {
		t.Error("GetCredential() returned empty string for new-format credential with non-token fields")
	}
}

func TestRegistry_GetCredential_ReturnsErrorWhenNoCredentialValueFound(t *testing.T) {
	// When the vault contains a new-format secret with only non-string values,
	// GetCredential should return an error.
	v := newMockVault()
	reg := services.NewRegistry(v)

	svc := services.Service{
		Name:   "weird",
		Type:   "http_proxy",
		Target: "https://example.com",
		Inject: "header",
	}
	if err := reg.CreateWithAuth(svc, "custom", map[string]string{"token": "abc"}); err != nil {
		t.Fatalf("CreateWithAuth() returned unexpected error: %v", err)
	}
	// Replace vault content with a new-format secret that has no string credential fields.
	v.mu.Lock()
	v.secrets["services/weird/credential"] = map[string]interface{}{
		"auth_method": "custom",
		// no string fields other than auth_method
	}
	v.mu.Unlock()

	_, err := reg.GetCredential("weird")
	if err == nil {
		t.Fatal("expected error when no credential value can be found, got nil")
	}
}

func TestRegistry_GetCredential_VaultError_ReturnsError(t *testing.T) {
	v := newMockVault()
	reg := services.NewRegistry(v)

	svc := services.Service{
		Name:   "github",
		Type:   "http_proxy",
		Target: "https://api.github.com",
		Inject: "header",
	}
	if err := reg.Create(svc, "ghp_token"); err != nil {
		t.Fatalf("Create() returned unexpected error: %v", err)
	}

	v.readErr["services/github/credential"] = errors.New("vault unavailable")

	_, err := reg.GetCredential("github")
	if err == nil {
		t.Fatal("expected error when vault read fails, got nil")
	}
}

func TestRegistry_GetCredential_RawLegacyFormat_NoAuthMethodKey(t *testing.T) {
	// Simulates a vault secret written before WP-MA-2 (no auth_method key).
	// GetCredential must still return the value field.
	v := newMockVault()
	reg := services.NewRegistry(v)

	svc := services.Service{
		Name:   "stripe",
		Type:   "http_proxy",
		Target: "https://api.stripe.com",
		Inject: "header",
	}
	if err := reg.CreateWithAuth(svc, "stripe_key", map[string]string{"token": "placeholder"}); err != nil {
		t.Fatalf("setup CreateWithAuth() returned unexpected error: %v", err)
	}
	// Replace with raw legacy format (no auth_method key).
	v.mu.Lock()
	v.secrets["services/stripe/credential"] = map[string]interface{}{
		"value": "sk_raw_legacy",
		"type":  "api_key",
	}
	v.mu.Unlock()

	cred, err := reg.GetCredential("stripe")
	if err != nil {
		t.Fatalf("GetCredential() returned unexpected error for raw legacy format: %v", err)
	}
	if cred != "sk_raw_legacy" {
		t.Errorf("expected cred=sk_raw_legacy, got %q", cred)
	}
}

func TestRegistry_GetCredential_RawLegacyFormat_MissingValueKey_ReturnsError(t *testing.T) {
	v := newMockVault()
	reg := services.NewRegistry(v)

	svc := services.Service{
		Name:   "stripe",
		Type:   "http_proxy",
		Target: "https://api.stripe.com",
		Inject: "header",
	}
	if err := reg.CreateWithAuth(svc, "stripe_key", map[string]string{"token": "placeholder"}); err != nil {
		t.Fatalf("setup CreateWithAuth() returned unexpected error: %v", err)
	}
	// Replace with legacy-ish format that has no value key.
	v.mu.Lock()
	v.secrets["services/stripe/credential"] = map[string]interface{}{
		"type": "api_key",
	}
	v.mu.Unlock()

	_, err := reg.GetCredential("stripe")
	if err == nil {
		t.Fatal("expected error for legacy format missing value key, got nil")
	}
}

// ---------------------------------------------------------------------------
// Registry.RotateCredential tests (pre-existing, adding coverage)
// ---------------------------------------------------------------------------

func TestRegistry_RotateCredential_UpdatesCredential(t *testing.T) {
	v := newMockVault()
	reg := services.NewRegistry(v)

	svc := services.Service{
		Name:   "stripe",
		Type:   "http_proxy",
		Target: "https://api.stripe.com",
		Inject: "header",
	}
	if err := reg.Create(svc, "sk_old"); err != nil {
		t.Fatalf("Create() returned unexpected error: %v", err)
	}

	if err := reg.RotateCredential("stripe", "sk_new"); err != nil {
		t.Fatalf("RotateCredential() returned unexpected error: %v", err)
	}

	cred, err := reg.GetCredential("stripe")
	if err != nil {
		t.Fatalf("GetCredential() after RotateCredential() returned unexpected error: %v", err)
	}
	if cred != "sk_new" {
		t.Errorf("expected credential=sk_new after rotation, got %q", cred)
	}
}

func TestRegistry_RotateCredential_ServiceNotFound_ReturnsError(t *testing.T) {
	v := newMockVault()
	reg := services.NewRegistry(v)

	err := reg.RotateCredential("nonexistent", "new-key")
	if err == nil {
		t.Fatal("expected error for non-existent service, got nil")
	}
}

// ---------------------------------------------------------------------------
// Vault metadata persistence tests (persistence bug fix)
// ---------------------------------------------------------------------------

// TestRegistry_Create_WritesMetadataToVault verifies that Create persists service
// metadata to vault at services/{name}/metadata in addition to the credential.
func TestRegistry_Create_WritesMetadataToVault(t *testing.T) {
	v := newMockVault()
	reg := services.NewRegistry(v)

	svc := services.Service{
		Name:           "github",
		Type:           "http_proxy",
		Target:         "https://api.github.com",
		Inject:         "header",
		HeaderName:     "Authorization",
		HeaderTemplate: "Bearer {{credential}}",
	}
	if err := reg.Create(svc, "ghp_token"); err != nil {
		t.Fatalf("Create() returned unexpected error: %v", err)
	}

	if !v.hasSecret("services/github/metadata") {
		t.Error("expected metadata to be stored in vault at services/github/metadata")
	}
}

// TestRegistry_CreateWithAuth_WritesMetadataToVault verifies that CreateWithAuth
// also persists metadata.
func TestRegistry_CreateWithAuth_WritesMetadataToVault(t *testing.T) {
	v := newMockVault()
	reg := services.NewRegistry(v)

	svc := services.Service{
		Name:   "aws",
		Type:   "http_proxy",
		Target: "https://s3.amazonaws.com",
		Inject: "header",
	}
	if err := reg.CreateWithAuth(svc, "access-key", map[string]string{
		"access_key_id":     "AKIAIOSFODNN7EXAMPLE",
		"secret_access_key": "wJalrXUtnFEMI",
	}); err != nil {
		t.Fatalf("CreateWithAuth() returned unexpected error: %v", err)
	}

	if !v.hasSecret("services/aws/metadata") {
		t.Error("expected metadata to be stored in vault at services/aws/metadata")
	}
}

// TestRegistry_Update_WritesMetadataToVault verifies that Update persists updated
// metadata.
func TestRegistry_Update_WritesMetadataToVault(t *testing.T) {
	v := newMockVault()
	reg := services.NewRegistry(v)

	svc := services.Service{
		Name:   "stripe",
		Type:   "http_proxy",
		Target: "https://api.stripe.com",
		Inject: "header",
	}
	if err := reg.Create(svc, "sk_old"); err != nil {
		t.Fatalf("Create() returned unexpected error: %v", err)
	}

	updated := services.Service{
		Name:   "stripe",
		Type:   "http_proxy",
		Target: "https://api.stripe.com/v2",
		Inject: "query",
	}
	if err := reg.Update("stripe", updated, nil); err != nil {
		t.Fatalf("Update() returned unexpected error: %v", err)
	}

	if !v.hasSecret("services/stripe/metadata") {
		t.Error("expected metadata to be stored in vault at services/stripe/metadata after Update()")
	}
}

// TestRegistry_Delete_RemovesMetadataFromVault verifies that Delete also removes
// the metadata path from vault (no orphaned metadata).
func TestRegistry_Delete_RemovesMetadataFromVault(t *testing.T) {
	v := newMockVault()
	reg := services.NewRegistry(v)

	svc := services.Service{
		Name:   "github",
		Type:   "http_proxy",
		Target: "https://api.github.com",
		Inject: "header",
	}
	if err := reg.Create(svc, "ghp_token"); err != nil {
		t.Fatalf("Create() returned unexpected error: %v", err)
	}

	if err := reg.Delete("github"); err != nil {
		t.Fatalf("Delete() returned unexpected error: %v", err)
	}

	if v.hasSecret("services/github/metadata") {
		t.Error("metadata still in vault after service deletion — orphaned metadata!")
	}
}

// TestRegistry_LoadFromVault_ReloadsPersistedServices verifies that LoadFromVault
// restores services from vault metadata written by a previous Create call.
func TestRegistry_LoadFromVault_ReloadsPersistedServices(t *testing.T) {
	v := newMockVault()

	// First registry instance: create a service (simulating pre-restart state).
	reg1 := services.NewRegistry(v)
	svc := services.Service{
		Name:           "github",
		Type:           "http_proxy",
		Target:         "https://api.github.com",
		Inject:         "header",
		HeaderName:     "Authorization",
		HeaderTemplate: "Bearer {{credential}}",
	}
	if err := reg1.Create(svc, "ghp_token"); err != nil {
		t.Fatalf("Create() returned unexpected error: %v", err)
	}

	// Second registry instance: simulates container restart — empty in-memory state.
	reg2 := services.NewRegistry(v)
	if err := reg2.LoadFromVault(); err != nil {
		t.Fatalf("LoadFromVault() returned unexpected error: %v", err)
	}

	got, err := reg2.Get("github")
	if err != nil {
		t.Fatalf("Get() returned unexpected error after LoadFromVault: %v", err)
	}
	if got.Name != "github" {
		t.Errorf("expected name=github, got %q", got.Name)
	}
	if got.Target != "https://api.github.com" {
		t.Errorf("expected target=https://api.github.com, got %q", got.Target)
	}
	if got.Type != "http_proxy" {
		t.Errorf("expected type=http_proxy, got %q", got.Type)
	}
	if got.Inject != "header" {
		t.Errorf("expected inject=header, got %q", got.Inject)
	}
	if got.Status != "available" {
		t.Errorf("expected status=available after load, got %q", got.Status)
	}
}

// TestRegistry_LoadFromVault_ReloadsDefaultHeaders verifies that default_headers
// are round-tripped through vault as a JSON string and correctly deserialized.
func TestRegistry_LoadFromVault_ReloadsDefaultHeaders(t *testing.T) {
	v := newMockVault()

	reg1 := services.NewRegistry(v)
	svc := services.Service{
		Name:           "anthropic",
		Type:           "http_proxy",
		Target:         "https://api.anthropic.com",
		Inject:         "header",
		DefaultHeaders: map[string]string{"anthropic-version": "2023-06-01"},
	}
	if err := reg1.Create(svc, "sk-ant-abc"); err != nil {
		t.Fatalf("Create() returned unexpected error: %v", err)
	}

	reg2 := services.NewRegistry(v)
	if err := reg2.LoadFromVault(); err != nil {
		t.Fatalf("LoadFromVault() returned unexpected error: %v", err)
	}

	got, err := reg2.Get("anthropic")
	if err != nil {
		t.Fatalf("Get() after LoadFromVault returned unexpected error: %v", err)
	}
	if got.DefaultHeaders["anthropic-version"] != "2023-06-01" {
		t.Errorf("expected DefaultHeaders[anthropic-version]=2023-06-01, got %q", got.DefaultHeaders["anthropic-version"])
	}
}

// TestRegistry_LoadFromVault_EmptyVault_ReturnsNilError verifies that LoadFromVault
// on an empty vault is a no-op that returns nil (not an error).
func TestRegistry_LoadFromVault_EmptyVault_ReturnsNilError(t *testing.T) {
	v := newMockVault()
	reg := services.NewRegistry(v)

	if err := reg.LoadFromVault(); err != nil {
		t.Errorf("LoadFromVault() on empty vault returned unexpected error: %v", err)
	}

	if len(reg.List()) != 0 {
		t.Errorf("expected 0 services after LoadFromVault on empty vault, got %d", len(reg.List()))
	}
}

// TestRegistry_LoadFromVault_SkipsServicesWithoutMetadata verifies that services
// that have credentials in vault but no metadata (legacy) are silently skipped.
func TestRegistry_LoadFromVault_SkipsServicesWithoutMetadata(t *testing.T) {
	v := newMockVault()

	// Manually plant a credential but no metadata (legacy service).
	v.mu.Lock()
	v.secrets["services/legacy/credential"] = map[string]interface{}{
		"value": "old-token",
	}
	v.mu.Unlock()

	// Plant metadata for a normal service so ListSecrets has something to return.
	// We do this by using a registry that writes metadata.
	reg1 := services.NewRegistry(v)
	svc := services.Service{
		Name:   "normal",
		Type:   "http_proxy",
		Target: "https://api.example.com",
		Inject: "header",
	}
	if err := reg1.Create(svc, "cred"); err != nil {
		t.Fatalf("Create() returned unexpected error: %v", err)
	}

	reg2 := services.NewRegistry(v)
	if err := reg2.LoadFromVault(); err != nil {
		t.Fatalf("LoadFromVault() returned unexpected error: %v", err)
	}

	// "normal" must be loaded; "legacy" must not appear (no metadata).
	_, err := reg2.Get("normal")
	if err != nil {
		t.Errorf("expected normal service to be loaded, got error: %v", err)
	}
	_, err = reg2.Get("legacy")
	if err == nil {
		t.Error("expected legacy service (no metadata) to be absent after LoadFromVault")
	}
}

// TestRegistry_LoadFromVault_DoesNotOverwriteExistingEntries verifies that
// LoadFromVault does not clobber services already in the registry (e.g. if
// LoadFromVault is called twice, the second call is a no-op for existing services).
func TestRegistry_LoadFromVault_DoesNotOverwriteExistingEntries(t *testing.T) {
	v := newMockVault()
	reg := services.NewRegistry(v)

	svc := services.Service{
		Name:   "stripe",
		Type:   "http_proxy",
		Target: "https://api.stripe.com",
		Inject: "header",
	}
	if err := reg.Create(svc, "sk_test"); err != nil {
		t.Fatalf("Create() returned unexpected error: %v", err)
	}

	// Mutate the in-memory service to simulate a mid-session state.
	if err := reg.SetAccountInfo("stripe", &services.AccountInfo{Username: "acme"}); err != nil {
		t.Fatalf("SetAccountInfo() returned unexpected error: %v", err)
	}

	// A second LoadFromVault call must not erase the account info.
	if err := reg.LoadFromVault(); err != nil {
		t.Fatalf("second LoadFromVault() returned unexpected error: %v", err)
	}

	got, err := reg.Get("stripe")
	if err != nil {
		t.Fatalf("Get() returned unexpected error: %v", err)
	}
	if got.AccountInfo == nil || got.AccountInfo.Username != "acme" {
		t.Error("LoadFromVault must not overwrite existing in-memory entry")
	}
}

// TestRegistry_LoadFromVault_HandlesTrailingSlashInListedNames verifies that
// vault list names with trailing slashes (e.g. "github/") are handled correctly.
func TestRegistry_LoadFromVault_HandlesTrailingSlashInListedNames(t *testing.T) {
	v := newMockVault()
	reg1 := services.NewRegistry(v)

	svc := services.Service{
		Name:   "github",
		Type:   "http_proxy",
		Target: "https://api.github.com",
		Inject: "header",
	}
	if err := reg1.Create(svc, "ghp_token"); err != nil {
		t.Fatalf("Create() returned unexpected error: %v", err)
	}

	// Simulate vault returning names with trailing slashes (real OpenBao behaviour).
	// Override ListSecrets in the mock to return "github/" instead of "github".
	v.mu.Lock()
	origSecrets := make(map[string]map[string]interface{})
	for k, val := range v.secrets {
		origSecrets[k] = val
	}
	v.mu.Unlock()

	// Replace the mock's ListSecrets to return trailing-slash names.
	// We achieve this by injecting a custom listKeys value via a wrapper mock.
	trailingSlashVault := &trailingSlashMock{mockVault: v}

	reg2 := services.NewRegistry(trailingSlashVault)
	if err := reg2.LoadFromVault(); err != nil {
		t.Fatalf("LoadFromVault() returned unexpected error with trailing slash names: %v", err)
	}

	_, err := reg2.Get("github")
	if err != nil {
		t.Errorf("expected service to be loaded despite trailing slash in list result: %v", err)
	}
}

// TestRegistry_LoadFromVault_MultipleServices verifies that all services
// persisted across multiple Create calls are restored by LoadFromVault.
func TestRegistry_LoadFromVault_MultipleServices(t *testing.T) {
	v := newMockVault()
	reg1 := services.NewRegistry(v)

	names := []string{"github", "stripe", "openai"}
	for _, name := range names {
		svc := services.Service{
			Name:   name,
			Type:   "http_proxy",
			Target: "https://api.example.com/" + name,
			Inject: "header",
		}
		if err := reg1.Create(svc, "cred-"+name); err != nil {
			t.Fatalf("Create(%q) returned unexpected error: %v", name, err)
		}
	}

	reg2 := services.NewRegistry(v)
	if err := reg2.LoadFromVault(); err != nil {
		t.Fatalf("LoadFromVault() returned unexpected error: %v", err)
	}

	list := reg2.List()
	if len(list) != len(names) {
		t.Errorf("expected %d services after LoadFromVault, got %d", len(names), len(list))
	}
}

// TestRegistry_Create_MetadataWriteFailure_ServiceStillCreated verifies that
// if metadata write fails, it is treated as best-effort and the service is still
// created (credential write succeeded).
// NOTE: This documents current design intent. Metadata write failures are logged
// but do not block service creation.
func TestRegistry_Create_MetadataWriteFailure_ServiceStillCreated(t *testing.T) {
	v := newMockVault()
	v.writeErr["services/mysvc/metadata"] = errors.New("vault metadata write failed")
	reg := services.NewRegistry(v)

	svc := services.Service{
		Name:   "mysvc",
		Type:   "http_proxy",
		Target: "https://api.example.com",
		Inject: "header",
	}
	// Service creation must succeed even if metadata write fails.
	if err := reg.Create(svc, "cred"); err != nil {
		t.Fatalf("Create() returned unexpected error when metadata write fails: %v", err)
	}

	// Service must be in-memory.
	_, err := reg.Get("mysvc")
	if err != nil {
		t.Errorf("service must be in registry even if metadata write failed: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Helper mock for trailing-slash test
// ---------------------------------------------------------------------------

// trailingSlashMock wraps mockVault and overrides ListSecrets to return names
// with trailing slashes, simulating real OpenBao list behaviour.
type trailingSlashMock struct {
	*mockVault
}

func (m *trailingSlashMock) ListSecrets(path string) ([]string, error) {
	keys, err := m.mockVault.ListSecrets(path)
	if err != nil {
		return nil, err
	}
	// Append trailing slash to each name to mimic vault directory listing.
	result := make([]string, len(keys))
	for i, k := range keys {
		result[i] = k + "/"
	}
	return result, nil
}

func TestRegistry_RotateCredential_VaultError_ReturnsError(t *testing.T) {
	v := newMockVault()
	reg := services.NewRegistry(v)

	svc := services.Service{
		Name:   "stripe",
		Type:   "http_proxy",
		Target: "https://api.stripe.com",
		Inject: "header",
	}
	if err := reg.Create(svc, "sk_old"); err != nil {
		t.Fatalf("Create() returned unexpected error: %v", err)
	}

	v.writeErr["services/stripe/credential"] = errors.New("vault write failed")

	err := reg.RotateCredential("stripe", "sk_new")
	if err == nil {
		t.Fatal("expected error when vault write fails, got nil")
	}
}
