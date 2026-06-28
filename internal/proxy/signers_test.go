// Package proxy_test — failing tests for custom_auth, hmac_signature, aws_sigv4 injectors.
// These tests are written RED-first; they will not compile until the implementation exists.
package proxy_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/straylight-ai/straylight/internal/proxy"
	"github.com/straylight-ai/straylight/internal/services"
)

// ---------------------------------------------------------------------------
// CustomAuthInjector
// ---------------------------------------------------------------------------

func TestCustomAuthInjector_RendersMultipleHeaders(t *testing.T) {
	req := newTestRequest(t, "https://api.example.com/v1/data")
	inj := &proxy.CustomAuthInjector{}

	cfg := services.InjectionConfig{
		Type: services.InjectionCustomAuth,
		Custom: &services.CustomAuthSpec{
			Headers: map[string]string{
				"X-API-Key":   "{{.api_key}}",
				"X-Client-ID": "{{.client_id}}",
			},
		},
	}
	fields := map[string]string{
		"api_key":   "secret-key-123",
		"client_id": "client-abc",
	}

	if err := inj.Inject(req, fields, cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := req.Header.Get("X-API-Key"); got != "secret-key-123" {
		t.Errorf("X-API-Key: expected 'secret-key-123', got %q", got)
	}
	if got := req.Header.Get("X-Client-ID"); got != "client-abc" {
		t.Errorf("X-Client-ID: expected 'client-abc', got %q", got)
	}
}

func TestCustomAuthInjector_RendersQueryParams(t *testing.T) {
	req := newTestRequest(t, "https://api.example.com/v1/data?existing=yes")
	inj := &proxy.CustomAuthInjector{}

	cfg := services.InjectionConfig{
		Type: services.InjectionCustomAuth,
		Custom: &services.CustomAuthSpec{
			Query: map[string]string{
				"api_key": "{{.token}}",
			},
		},
	}
	fields := map[string]string{"token": "mytoken"}

	if err := inj.Inject(req, fields, cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	q := req.URL.Query()
	if got := q.Get("api_key"); got != "mytoken" {
		t.Errorf("api_key: expected 'mytoken', got %q", got)
	}
	if got := q.Get("existing"); got != "yes" {
		t.Errorf("existing param lost: got %q", got)
	}
}

func TestCustomAuthInjector_BodyJSON_MergesAndResetsContentLength(t *testing.T) {
	existingBody := []byte(`{"foo":"bar"}`)
	req := newTestRequest(t, "https://api.example.com/v1/resource")
	req.Method = http.MethodPost
	req.Body = io.NopCloser(bytes.NewBuffer(existingBody))
	req.ContentLength = int64(len(existingBody))

	inj := &proxy.CustomAuthInjector{}
	cfg := services.InjectionConfig{
		Type: services.InjectionCustomAuth,
		Custom: &services.CustomAuthSpec{
			Body: map[string]string{
				"api_key": "{{.api_key}}",
			},
			BodyMode: "json",
		},
	}
	fields := map[string]string{"api_key": "injected-key"}

	if err := inj.Inject(req, fields, cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	body, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("reading body: %v", err)
	}
	var got map[string]interface{}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("unmarshal body: %v", err)
	}
	if got["foo"] != "bar" {
		t.Errorf("existing key 'foo' lost: %v", got)
	}
	if got["api_key"] != "injected-key" {
		t.Errorf("injected key 'api_key' not found: %v", got)
	}
	if req.ContentLength != int64(len(body)) {
		t.Errorf("ContentLength = %d, want %d", req.ContentLength, len(body))
	}
}

func TestCustomAuthInjector_BodyForm_ProducesURLEncoded(t *testing.T) {
	req := newTestRequest(t, "https://api.example.com/v1/form")
	req.Method = http.MethodPost

	inj := &proxy.CustomAuthInjector{}
	cfg := services.InjectionConfig{
		Type: services.InjectionCustomAuth,
		Custom: &services.CustomAuthSpec{
			Body: map[string]string{
				"grant_type": "client_credentials",
				"client_id":  "{{.client_id}}",
			},
			BodyMode: "form",
		},
	}
	fields := map[string]string{"client_id": "myclient"}

	if err := inj.Inject(req, fields, cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	body, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("reading body: %v", err)
	}

	bodyStr := string(body)
	if !containsStr(bodyStr, "client_id=myclient") {
		t.Errorf("expected client_id=myclient in %q", bodyStr)
	}
	if !containsStr(bodyStr, "grant_type=client_credentials") {
		t.Errorf("expected grant_type=client_credentials in %q", bodyStr)
	}
}

func TestCustomAuthInjector_NilCustomReturnsError(t *testing.T) {
	req := newTestRequest(t, "https://api.example.com/")
	inj := &proxy.CustomAuthInjector{}

	cfg := services.InjectionConfig{
		Type:   services.InjectionCustomAuth,
		Custom: nil,
	}
	fields := map[string]string{"token": "val"}

	err := inj.Inject(req, fields, cfg)
	if err == nil {
		t.Fatal("expected error for nil Custom, got nil")
	}
	if !containsStr(err.Error(), "custom_auth") {
		t.Errorf("error should mention 'custom_auth': %v", err)
	}
}

func TestCustomAuthInjector_MissingFieldReturnsErrorWithKeyNotValue(t *testing.T) {
	req := newTestRequest(t, "https://api.example.com/")
	inj := &proxy.CustomAuthInjector{}

	cfg := services.InjectionConfig{
		Type: services.InjectionCustomAuth,
		Custom: &services.CustomAuthSpec{
			Headers: map[string]string{
				"X-Secret": "{{.missing_field}}",
			},
		},
	}
	fields := map[string]string{"other_field": "supersecretvalue"}

	err := inj.Inject(req, fields, cfg)
	if err == nil {
		t.Fatal("expected error for missing field, got nil")
	}
	if !containsStr(err.Error(), "missing_field") {
		t.Errorf("error should mention 'missing_field': %v", err)
	}
	if containsStr(err.Error(), "supersecretvalue") {
		t.Errorf("error must not expose credential value: %v", err)
	}
}

func TestCustomAuthInjector_SafeFuncUpper(t *testing.T) {
	req := newTestRequest(t, "https://api.example.com/")
	inj := &proxy.CustomAuthInjector{}

	cfg := services.InjectionConfig{
		Type: services.InjectionCustomAuth,
		Custom: &services.CustomAuthSpec{
			Headers: map[string]string{
				"X-Token": `{{upper .token}}`,
			},
		},
	}
	fields := map[string]string{"token": "lowercase"}

	if err := inj.Inject(req, fields, cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := req.Header.Get("X-Token"); got != "LOWERCASE" {
		t.Errorf("expected 'LOWERCASE', got %q", got)
	}
}

func TestCustomAuthInjector_SafeFuncLower(t *testing.T) {
	req := newTestRequest(t, "https://api.example.com/")
	inj := &proxy.CustomAuthInjector{}

	cfg := services.InjectionConfig{
		Type: services.InjectionCustomAuth,
		Custom: &services.CustomAuthSpec{
			Headers: map[string]string{
				"X-Token": `{{lower .token}}`,
			},
		},
	}
	fields := map[string]string{"token": "UPPERCASE"}

	if err := inj.Inject(req, fields, cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := req.Header.Get("X-Token"); got != "uppercase" {
		t.Errorf("expected 'uppercase', got %q", got)
	}
}

func TestCustomAuthInjector_SafeFuncBase64(t *testing.T) {
	req := newTestRequest(t, "https://api.example.com/")
	inj := &proxy.CustomAuthInjector{}

	cfg := services.InjectionConfig{
		Type: services.InjectionCustomAuth,
		Custom: &services.CustomAuthSpec{
			Headers: map[string]string{
				"X-Encoded": `{{base64 .api_key}}`,
			},
		},
	}
	fields := map[string]string{"api_key": "api_key_value"}

	if err := inj.Inject(req, fields, cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// base64("api_key_value") = "YXBpX2tleV92YWx1ZQ=="
	if got := req.Header.Get("X-Encoded"); got != "YXBpX2tleV92YWx1ZQ==" {
		t.Errorf("expected 'YXBpX2tleV92YWx1ZQ==', got %q", got)
	}
}

// ---------------------------------------------------------------------------
// HMACInjector
// ---------------------------------------------------------------------------

func TestHMACInjector_SHA256Hex(t *testing.T) {
	req := newTestRequest(t, "https://api.example.com/api/test")
	req.Method = http.MethodGet

	inj := &proxy.HMACInjector{}

	cfg := services.InjectionConfig{
		Type: services.InjectionHMACSignature,
		Sign: &services.SignSpec{
			HMAC: &services.HMACSpec{
				Algorithm:    "sha256",
				Encoding:     "hex",
				HeaderName:   "X-Signature",
				SecretField:  "secret",
				SignedString: "{{.method}}.{{.path}}",
			},
		},
	}
	fields := map[string]string{"secret": "testkey"}

	if err := inj.Inject(req, fields, cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// HMAC-SHA256("testkey", "GET./api/test") = a52036bea4735a35460101edb146219c07af4c84de216ab427ab72bc5a390384
	got := req.Header.Get("X-Signature")
	if got != "a52036bea4735a35460101edb146219c07af4c84de216ab427ab72bc5a390384" {
		t.Errorf("X-Signature: expected known SHA256 vector, got %q", got)
	}
}

func TestHMACInjector_SHA512Base64(t *testing.T) {
	req := newTestRequest(t, "https://api.example.com/api/test")
	req.Method = http.MethodGet

	inj := &proxy.HMACInjector{}

	cfg := services.InjectionConfig{
		Type: services.InjectionHMACSignature,
		Sign: &services.SignSpec{
			HMAC: &services.HMACSpec{
				Algorithm:    "sha512",
				Encoding:     "base64",
				HeaderName:   "X-Signature",
				SecretField:  "secret",
				SignedString: "{{.method}}.{{.path}}",
			},
		},
	}
	fields := map[string]string{"secret": "testkey"}

	if err := inj.Inject(req, fields, cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// HMAC-SHA512("testkey", "GET./api/test") base64
	got := req.Header.Get("X-Signature")
	if got != "D2M0McD0kWPEhzDlDf7P4gLCjYgkWoQg77PP9fGoXur67X7SySQIiLutTxlqvBgrB/A9BQUH9rm7bF5+11X1aw==" {
		t.Errorf("X-Signature: expected known SHA512 base64 vector, got %q", got)
	}
}

func TestHMACInjector_HeaderPrefix(t *testing.T) {
	req := newTestRequest(t, "https://api.example.com/webhook")
	req.Method = http.MethodPost

	inj := &proxy.HMACInjector{}

	cfg := services.InjectionConfig{
		Type: services.InjectionHMACSignature,
		Sign: &services.SignSpec{
			HMAC: &services.HMACSpec{
				Algorithm:    "sha256",
				Encoding:     "hex",
				HeaderName:   "X-Hub-Signature-256",
				HeaderPrefix: "sha256=",
				SecretField:  "secret",
				SignedString: "POST./webhook",
			},
		},
	}
	fields := map[string]string{"secret": "webhooksecret"}

	if err := inj.Inject(req, fields, cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// HMAC-SHA256("webhooksecret", "POST./webhook") with prefix "sha256="
	got := req.Header.Get("X-Hub-Signature-256")
	if !strings.HasPrefix(got, "sha256=") {
		t.Errorf("X-Hub-Signature-256: expected 'sha256=' prefix, got %q", got)
	}
	if got != "sha256=9687847f5ed7694be0d041ed207a17cda3fb9bc314afd2850981748fd7c5193e" {
		t.Errorf("X-Hub-Signature-256: expected known vector, got %q", got)
	}
}

func TestHMACInjector_IncludeTimestamp_SetsHeaderAndExposesInTemplate(t *testing.T) {
	pinnedTime := time.Unix(1700000000, 0)

	req := newTestRequest(t, "https://hooks.slack.com/webhook")
	req.Method = http.MethodPost
	bodyPayload := []byte(`{"text":"hello"}`)
	req.Body = io.NopCloser(bytes.NewBuffer(bodyPayload))
	req.ContentLength = int64(len(bodyPayload))

	inj := &proxy.HMACInjector{
		Now: func() time.Time { return pinnedTime },
	}

	cfg := services.InjectionConfig{
		Type: services.InjectionHMACSignature,
		Sign: &services.SignSpec{
			HMAC: &services.HMACSpec{
				Algorithm:        "sha256",
				Encoding:         "hex",
				HeaderName:       "X-Slack-Signature",
				HeaderPrefix:     "v0=",
				SecretField:      "secret",
				SignedString:     `v0:{{.timestamp}}:{{.body}}`,
				IncludeTimestamp: true,
				TimestampHeader:  "X-Slack-Request-Timestamp",
			},
		},
	}
	fields := map[string]string{"secret": "slacksecret"}

	if err := inj.Inject(req, fields, cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := req.Header.Get("X-Slack-Request-Timestamp"); got != "1700000000" {
		t.Errorf("X-Slack-Request-Timestamp: expected '1700000000', got %q", got)
	}

	// HMAC-SHA256("slacksecret", "v0:1700000000:{\"text\":\"hello\"}") with prefix "v0="
	got := req.Header.Get("X-Slack-Signature")
	if !strings.HasPrefix(got, "v0=") {
		t.Errorf("X-Slack-Signature: expected 'v0=' prefix, got %q", got)
	}
	if got != "v0=f96fe1ac73c94ffe46bdc5b4bf6599475c033723ab19be29f64614b582f175a0" {
		t.Errorf("X-Slack-Signature: expected known vector, got %q", got)
	}
}

func TestHMACInjector_MissingSecretFieldReturnsError(t *testing.T) {
	req := newTestRequest(t, "https://api.example.com/")
	inj := &proxy.HMACInjector{}

	cfg := services.InjectionConfig{
		Type: services.InjectionHMACSignature,
		Sign: &services.SignSpec{
			HMAC: &services.HMACSpec{
				Algorithm:    "sha256",
				Encoding:     "hex",
				HeaderName:   "X-Signature",
				SecretField:  "webhook_secret",
				SignedString: "{{.body}}",
			},
		},
	}
	fields := map[string]string{"other": "val"}

	err := inj.Inject(req, fields, cfg)
	if err == nil {
		t.Fatal("expected error for missing secret field, got nil")
	}
}

func TestHMACInjector_UnknownAlgorithmReturnsError(t *testing.T) {
	req := newTestRequest(t, "https://api.example.com/")
	inj := &proxy.HMACInjector{}

	cfg := services.InjectionConfig{
		Type: services.InjectionHMACSignature,
		Sign: &services.SignSpec{
			HMAC: &services.HMACSpec{
				Algorithm:    "md5",
				Encoding:     "hex",
				HeaderName:   "X-Sig",
				SecretField:  "secret",
				SignedString: "{{.body}}",
			},
		},
	}
	fields := map[string]string{"secret": "key"}

	err := inj.Inject(req, fields, cfg)
	if err == nil {
		t.Fatal("expected error for unknown algorithm, got nil")
	}
}

func TestHMACInjector_NilSignReturnsError(t *testing.T) {
	req := newTestRequest(t, "https://api.example.com/")
	inj := &proxy.HMACInjector{}

	cfg := services.InjectionConfig{
		Type: services.InjectionHMACSignature,
		Sign: nil,
	}
	fields := map[string]string{"secret": "key"}

	err := inj.Inject(req, fields, cfg)
	if err == nil {
		t.Fatal("expected error for nil Sign, got nil")
	}
}

func TestHMACInjector_BodyReadAndRestored(t *testing.T) {
	body := []byte(`{"data":"value"}`)
	req := newTestRequest(t, "https://api.example.com/api/v1")
	req.Method = http.MethodPost
	req.Body = io.NopCloser(bytes.NewBuffer(body))
	req.ContentLength = int64(len(body))

	inj := &proxy.HMACInjector{}

	cfg := services.InjectionConfig{
		Type: services.InjectionHMACSignature,
		Sign: &services.SignSpec{
			HMAC: &services.HMACSpec{
				Algorithm:    "sha256",
				Encoding:     "hex",
				HeaderName:   "X-Sig",
				SecretField:  "secret",
				SignedString: "{{.body}}",
			},
		},
	}
	fields := map[string]string{"secret": "k"}

	if err := inj.Inject(req, fields, cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	restored, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("reading restored body: %v", err)
	}
	if string(restored) != string(body) {
		t.Errorf("body not restored: got %q, want %q", string(restored), string(body))
	}
}

// ---------------------------------------------------------------------------
// AWSSigV4Injector
// ---------------------------------------------------------------------------

func TestAWSSigV4Injector_AuthorizationHeaderSet(t *testing.T) {
	pinnedTime := time.Date(2013, 5, 24, 0, 0, 0, 0, time.UTC)

	req := newTestRequest(t, "https://examplebucket.s3.amazonaws.com/test.txt")
	req.Method = http.MethodGet

	inj := &proxy.AWSSigV4Injector{
		Now: func() time.Time { return pinnedTime },
	}

	cfg := services.InjectionConfig{
		Type: services.InjectionAWSSigV4,
		Sign: &services.SignSpec{
			AWS: &services.AWSSignSpec{
				Region:  "us-east-1",
				Service: "s3",
			},
		},
	}
	fields := map[string]string{
		"access_key_id":     "AKIAIOSFODNN7EXAMPLE",
		"secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	}

	if err := inj.Inject(req, fields, cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	auth := req.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256") {
		t.Errorf("Authorization: expected 'AWS4-HMAC-SHA256' prefix, got %q", auth)
	}
	if !containsStr(auth, "20130524/us-east-1/s3/aws4_request") {
		t.Errorf("Authorization: expected credential scope '20130524/us-east-1/s3/aws4_request', got %q", auth)
	}
	if got := req.Header.Get("X-Amz-Date"); got == "" {
		t.Error("X-Amz-Date not set")
	}
}

func TestAWSSigV4Injector_SessionTokenSetsSecurityHeader(t *testing.T) {
	pinnedTime := time.Date(2013, 5, 24, 0, 0, 0, 0, time.UTC)

	req := newTestRequest(t, "https://examplebucket.s3.amazonaws.com/test.txt")
	req.Method = http.MethodGet

	inj := &proxy.AWSSigV4Injector{
		Now: func() time.Time { return pinnedTime },
	}

	cfg := services.InjectionConfig{
		Type: services.InjectionAWSSigV4,
		Sign: &services.SignSpec{
			AWS: &services.AWSSignSpec{
				Region:  "us-east-1",
				Service: "s3",
			},
		},
	}
	fields := map[string]string{
		"access_key_id":     "ASIAIOSFODNN7EXAMPLE",
		"secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		"session_token":     "FwoGZXIvYXdzEJr//////////wEaDAUe...",
	}

	if err := inj.Inject(req, fields, cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got := req.Header.Get("X-Amz-Security-Token")
	if got != "FwoGZXIvYXdzEJr//////////wEaDAUe..." {
		t.Errorf("X-Amz-Security-Token: expected session token, got %q", got)
	}
}

func TestAWSSigV4Injector_RegionFromFieldOverridesConfig(t *testing.T) {
	pinnedTime := time.Date(2013, 5, 24, 0, 0, 0, 0, time.UTC)

	req := newTestRequest(t, "https://s3.eu-west-1.amazonaws.com/mybucket/obj")
	req.Method = http.MethodGet

	inj := &proxy.AWSSigV4Injector{
		Now: func() time.Time { return pinnedTime },
	}

	cfg := services.InjectionConfig{
		Type: services.InjectionAWSSigV4,
		Sign: &services.SignSpec{
			AWS: &services.AWSSignSpec{
				Region:  "us-east-1",
				Service: "s3",
			},
		},
	}
	fields := map[string]string{
		"access_key_id":     "AKIAIOSFODNN7EXAMPLE",
		"secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		"region":            "eu-west-1",
	}

	if err := inj.Inject(req, fields, cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	auth := req.Header.Get("Authorization")
	if !containsStr(auth, "eu-west-1/s3/aws4_request") {
		t.Errorf("Authorization: expected 'eu-west-1/s3/aws4_request' in credential scope, got %q", auth)
	}
}

func TestAWSSigV4Injector_MissingAccessKeyReturnsError(t *testing.T) {
	req := newTestRequest(t, "https://s3.amazonaws.com/bucket/key")
	req.Method = http.MethodGet

	inj := &proxy.AWSSigV4Injector{}

	cfg := services.InjectionConfig{
		Type: services.InjectionAWSSigV4,
		Sign: &services.SignSpec{
			AWS: &services.AWSSignSpec{Region: "us-east-1", Service: "s3"},
		},
	}
	fields := map[string]string{"secret_access_key": "secret"}

	err := inj.Inject(req, fields, cfg)
	if err == nil {
		t.Fatal("expected error for missing access_key_id, got nil")
	}
}

func TestAWSSigV4Injector_NilSignReturnsError(t *testing.T) {
	req := newTestRequest(t, "https://s3.amazonaws.com/bucket/key")
	req.Method = http.MethodGet

	inj := &proxy.AWSSigV4Injector{}

	cfg := services.InjectionConfig{
		Type: services.InjectionAWSSigV4,
		Sign: nil,
	}
	fields := map[string]string{
		"access_key_id":     "AKID",
		"secret_access_key": "secret",
	}

	err := inj.Inject(req, fields, cfg)
	if err == nil {
		t.Fatal("expected error for nil Sign, got nil")
	}
}

func TestAWSSigV4Injector_BodyHashedAndBodyRestored(t *testing.T) {
	pinnedTime := time.Date(2013, 5, 24, 0, 0, 0, 0, time.UTC)
	bodyContent := []byte(`{"key":"value"}`)

	req := newTestRequest(t, "https://api.execute-api.us-east-1.amazonaws.com/prod/resource")
	req.Method = http.MethodPost
	req.Body = io.NopCloser(bytes.NewBuffer(bodyContent))
	req.ContentLength = int64(len(bodyContent))

	inj := &proxy.AWSSigV4Injector{
		Now: func() time.Time { return pinnedTime },
	}

	cfg := services.InjectionConfig{
		Type: services.InjectionAWSSigV4,
		Sign: &services.SignSpec{
			AWS: &services.AWSSignSpec{
				Region:  "us-east-1",
				Service: "execute-api",
			},
		},
	}
	fields := map[string]string{
		"access_key_id":     "AKIAIOSFODNN7EXAMPLE",
		"secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	}

	if err := inj.Inject(req, fields, cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	restored, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("reading restored body: %v", err)
	}
	if string(restored) != string(bodyContent) {
		t.Errorf("body not restored: got %q, want %q", string(restored), string(bodyContent))
	}
}

// ---------------------------------------------------------------------------
// DefaultInjectorRegistry — new types registered
// ---------------------------------------------------------------------------

func TestDefaultInjectorRegistry_HasNewInjectors(t *testing.T) {
	r := proxy.DefaultInjectorRegistry()

	newTypes := []string{
		string(services.InjectionCustomAuth),
		string(services.InjectionHMACSignature),
		string(services.InjectionAWSSigV4),
	}
	for _, name := range newTypes {
		inj, err := r.Get(name)
		if err != nil {
			t.Errorf("new injector %q not registered: %v", name, err)
		}
		if inj == nil {
			t.Errorf("new injector %q returned nil", name)
		}
	}
}

func TestDefaultInjectorRegistry_LegacyAWSSigV4StrategyKey(t *testing.T) {
	r := proxy.DefaultInjectorRegistry()

	inj, err := r.Get("aws_sigv4")
	if err != nil {
		t.Errorf("legacy 'aws_sigv4' strategy key not registered: %v", err)
	}
	if inj == nil {
		t.Errorf("legacy 'aws_sigv4' returned nil injector")
	}
}

func TestCustomAuthInjector_BodyJSON_BadExistingBodyReturnsError(t *testing.T) {
	req := newTestRequest(t, "https://api.example.com/v1/resource")
	req.Method = http.MethodPost
	badBody := []byte(`not-valid-json`)
	req.Body = io.NopCloser(bytes.NewBuffer(badBody))
	req.ContentLength = int64(len(badBody))

	inj := &proxy.CustomAuthInjector{}
	cfg := services.InjectionConfig{
		Type: services.InjectionCustomAuth,
		Custom: &services.CustomAuthSpec{
			Body: map[string]string{
				"key": "{{.token}}",
			},
			BodyMode: "json",
		},
	}
	fields := map[string]string{"token": "val"}

	err := inj.Inject(req, fields, cfg)
	if err == nil {
		t.Fatal("expected error for invalid JSON body, got nil")
	}
}

func TestHMACInjector_UnknownEncodingReturnsError(t *testing.T) {
	req := newTestRequest(t, "https://api.example.com/")
	inj := &proxy.HMACInjector{}

	cfg := services.InjectionConfig{
		Type: services.InjectionHMACSignature,
		Sign: &services.SignSpec{
			HMAC: &services.HMACSpec{
				Algorithm:    "sha256",
				Encoding:     "binary", // not allowed
				HeaderName:   "X-Sig",
				SecretField:  "secret",
				SignedString: "{{.body}}",
			},
		},
	}
	fields := map[string]string{"secret": "key"}

	err := inj.Inject(req, fields, cfg)
	if err == nil {
		t.Fatal("expected error for unknown encoding, got nil")
	}
}

func TestAWSSigV4Injector_MissingSecretKeyReturnsError(t *testing.T) {
	req := newTestRequest(t, "https://s3.amazonaws.com/bucket/key")
	req.Method = http.MethodGet

	inj := &proxy.AWSSigV4Injector{}

	cfg := services.InjectionConfig{
		Type: services.InjectionAWSSigV4,
		Sign: &services.SignSpec{
			AWS: &services.AWSSignSpec{Region: "us-east-1", Service: "s3"},
		},
	}
	// Missing secret_access_key.
	fields := map[string]string{"access_key_id": "AKID"}

	err := inj.Inject(req, fields, cfg)
	if err == nil {
		t.Fatal("expected error for missing secret_access_key, got nil")
	}
}
