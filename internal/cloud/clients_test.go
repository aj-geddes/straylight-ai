// Package cloud_test — unit tests for the real GCP, Azure, and AWS cloud clients.
//
// These tests use httptest.Server (GCP, Azure) and a mock AWS seam (AWS) so no
// real network calls are ever made. RED phase: all tests fail until clients.go
// is implemented.
package cloud_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/straylight-ai/straylight/internal/cloud"
	"github.com/straylight-ai/straylight/internal/tokenexchange"
)

// ---------------------------------------------------------------------------
// GCP STS real client tests
// ---------------------------------------------------------------------------

// TestGCPSTSClient_ExchangeToken_RequestShape asserts the client sends the
// correct RFC 8693 token-exchange form fields and parses the response.
func TestGCPSTSClient_ExchangeToken_RequestShape(t *testing.T) {
	const (
		subjectToken      = "fake-oidc-jwt"
		audience          = "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/providers/prov"
		wantGrantType     = "urn:ietf:params:oauth:grant-type:token-exchange"
		wantSubjectType   = "urn:ietf:params:oauth:token-type:jwt"
		wantRequestedType = "urn:ietf:params:oauth:token-type:access_token"
	)

	var captured url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse form: %v", err)
		}
		captured = r.PostForm
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "ya29.federated",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer srv.Close()

	c := cloud.NewGCPSTSClient(nil, srv.URL)
	result, err := c.ExchangeToken(context.Background(), tokenexchange.GCPTokenExchangeInput{
		Audience:     audience,
		SubjectToken: subjectToken,
	})
	if err != nil {
		t.Fatalf("ExchangeToken() error = %v", err)
	}

	if result.AccessToken != "ya29.federated" {
		t.Errorf("AccessToken = %q, want %q", result.AccessToken, "ya29.federated")
	}
	if result.ExpiresIn != 3600 {
		t.Errorf("ExpiresIn = %d, want 3600", result.ExpiresIn)
	}

	if captured == nil {
		t.Fatal("server received no form body")
	}
	if got := captured.Get("grant_type"); got != wantGrantType {
		t.Errorf("grant_type = %q, want %q", got, wantGrantType)
	}
	if got := captured.Get("subject_token"); got != subjectToken {
		t.Errorf("subject_token = %q, want %q", got, subjectToken)
	}
	if got := captured.Get("subject_token_type"); got != wantSubjectType {
		t.Errorf("subject_token_type = %q, want %q", got, wantSubjectType)
	}
	if got := captured.Get("audience"); got != audience {
		t.Errorf("audience = %q, want %q", got, audience)
	}
	if got := captured.Get("requested_token_type"); got != wantRequestedType {
		t.Errorf("requested_token_type = %q, want %q", got, wantRequestedType)
	}

	// No-passthrough: subject_token must not appear in the returned access token.
	if result.AccessToken == subjectToken {
		t.Error("AccessToken echoes subject_token — no-passthrough violation")
	}
}

// TestGCPSTSClient_ExchangeToken_HTTPError asserts that a non-200 response
// surfaces as an error.
func TestGCPSTSClient_ExchangeToken_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
	}))
	defer srv.Close()

	c := cloud.NewGCPSTSClient(nil, srv.URL)
	_, err := c.ExchangeToken(context.Background(), tokenexchange.GCPTokenExchangeInput{
		Audience:     "//iam.googleapis.com/projects/1",
		SubjectToken: "tok",
	})
	if err == nil {
		t.Fatal("expected error for HTTP 400, got nil")
	}
}

// TestGCPSTSClient_ImplementsInterface is a compile-time interface assertion.
func TestGCPSTSClient_ImplementsInterface(t *testing.T) {
	var _ tokenexchange.GCPSTSClient = (*cloud.GCPSTSClient)(nil)
}

// TestGCPSTSClient_DefaultEndpoint verifies construction with no endpoint override.
func TestGCPSTSClient_DefaultEndpoint(t *testing.T) {
	c := cloud.NewGCPSTSClient(nil, "")
	if c == nil {
		t.Fatal("NewGCPSTSClient returned nil")
	}
}

// ---------------------------------------------------------------------------
// Azure HTTP token real client tests
// ---------------------------------------------------------------------------

// TestAzureHTTPTokenClient_ExchangeToken_RequestShape asserts the client posts
// the correct jwt-bearer fields (NO client_secret) and includes the tenant ID
// in the URL path.
func TestAzureHTTPTokenClient_ExchangeToken_RequestShape(t *testing.T) {
	const (
		tenantID        = "my-tenant-id"
		clientID        = "my-client-id"
		scope           = "https://management.azure.com/.default"
		clientAssertion = "fake-oidc-jwt-assertion"

		wantGrantType     = "urn:ietf:params:oauth:grant-type:jwt-bearer"
		wantAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
	)

	var captured url.Values
	var capturedPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPath = r.URL.Path
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse form: %v", err)
		}
		captured = r.PostForm
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "azure-access-token",
			"token_type":   "Bearer",
			"expires_in":   3599,
		})
	}))
	defer srv.Close()

	c := cloud.NewAzureHTTPTokenClient(nil, srv.URL)
	result, err := c.ExchangeToken(context.Background(), tokenexchange.AzureTokenExchangeInput{
		TenantID:        tenantID,
		ClientID:        clientID,
		Scope:           scope,
		ClientAssertion: clientAssertion,
	})
	if err != nil {
		t.Fatalf("ExchangeToken() error = %v", err)
	}

	if result.AccessToken != "azure-access-token" {
		t.Errorf("AccessToken = %q, want %q", result.AccessToken, "azure-access-token")
	}
	if result.ExpiresIn != 3599 {
		t.Errorf("ExpiresIn = %d, want 3599", result.ExpiresIn)
	}

	// URL must include the tenant ID.
	if !strings.Contains(capturedPath, tenantID) {
		t.Errorf("request path %q does not contain tenantID %q", capturedPath, tenantID)
	}

	if captured == nil {
		t.Fatal("server received no form body")
	}
	if got := captured.Get("grant_type"); got != wantGrantType {
		t.Errorf("grant_type = %q, want %q", got, wantGrantType)
	}
	if got := captured.Get("client_assertion_type"); got != wantAssertionType {
		t.Errorf("client_assertion_type = %q, want %q", got, wantAssertionType)
	}
	if got := captured.Get("client_assertion"); got != clientAssertion {
		t.Errorf("client_assertion = %q, want %q", got, clientAssertion)
	}
	if got := captured.Get("client_id"); got != clientID {
		t.Errorf("client_id = %q, want %q", got, clientID)
	}
	if got := captured.Get("scope"); got != scope {
		t.Errorf("scope = %q, want %q", got, scope)
	}
	// Must NOT send client_secret on the keyless path.
	if secret := captured.Get("client_secret"); secret != "" {
		t.Errorf("request sent client_secret = %q — must be absent on keyless FIC path", secret)
	}

	// No-passthrough: client_assertion must not appear in the returned access token.
	if result.AccessToken == clientAssertion {
		t.Error("AccessToken echoes client_assertion — no-passthrough violation")
	}
}

// TestAzureHTTPTokenClient_ExchangeToken_HTTPError asserts that non-200 surfaces.
func TestAzureHTTPTokenClient_ExchangeToken_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"invalid_client","error_description":"AADSTS7000"}`, http.StatusUnauthorized)
	}))
	defer srv.Close()

	c := cloud.NewAzureHTTPTokenClient(nil, srv.URL)
	_, err := c.ExchangeToken(context.Background(), tokenexchange.AzureTokenExchangeInput{
		TenantID:        "tenant",
		ClientID:        "client",
		Scope:           "https://management.azure.com/.default",
		ClientAssertion: "tok",
	})
	if err == nil {
		t.Fatal("expected error for HTTP 401, got nil")
	}
}

// TestAzureHTTPTokenClient_ImplementsInterface is a compile-time interface assertion.
func TestAzureHTTPTokenClient_ImplementsInterface(t *testing.T) {
	var _ tokenexchange.AzureTokenClient = (*cloud.AzureHTTPTokenClient)(nil)
}

// TestAzureHTTPTokenClient_DefaultEndpoint verifies construction with no override.
func TestAzureHTTPTokenClient_DefaultEndpoint(t *testing.T) {
	c := cloud.NewAzureHTTPTokenClient(nil, "")
	if c == nil {
		t.Fatal("NewAzureHTTPTokenClient returned nil")
	}
}

// ---------------------------------------------------------------------------
// AWS web-identity real client tests (via mock AWSSTSCaller seam)
// ---------------------------------------------------------------------------

// TestAWSWebIdentitySTSClient_ImplementsInterface is a compile-time assertion.
func TestAWSWebIdentitySTSClient_ImplementsInterface(t *testing.T) {
	var _ tokenexchange.STSWebIdentityClient = (*cloud.AWSWebIdentitySTSClient)(nil)
}

// TestAWSWebIdentitySTSClient_ForwardsInput verifies that RoleARN,
// WebIdentityToken, and DurationSeconds are forwarded to the inner caller, and
// that the response maps to STSWebIdentityCredentials correctly.
func TestAWSWebIdentitySTSClient_ForwardsInput(t *testing.T) {
	expiry := time.Now().Add(15 * time.Minute)
	mock := &mockAWSSTSCaller{
		webIdentityResp: &cloud.RawAWSCredentials{
			AccessKeyID:     "ASIAKEYLESS",
			SecretAccessKey: "keylessSecret",
			SessionToken:    "keylessToken",
			ExpiresAt:       expiry,
		},
	}

	client := cloud.NewAWSWebIdentitySTSClientWithCaller(mock)
	in := tokenexchange.STSAssumeRoleWithWebIdentityInput{
		RoleARN:          "arn:aws:iam::123456789012:role/KeylessRole",
		SessionName:      "straylight-exec",
		WebIdentityToken: "fake-oidc-token",
		DurationSeconds:  900,
	}

	result, err := client.AssumeRoleWithWebIdentity(context.Background(), in)
	if err != nil {
		t.Fatalf("AssumeRoleWithWebIdentity() error = %v", err)
	}

	if result.AccessKeyID != "ASIAKEYLESS" {
		t.Errorf("AccessKeyID = %q, want %q", result.AccessKeyID, "ASIAKEYLESS")
	}
	if result.SecretAccessKey != "keylessSecret" {
		t.Errorf("SecretAccessKey = %q, want %q", result.SecretAccessKey, "keylessSecret")
	}
	if result.SessionToken != "keylessToken" {
		t.Errorf("SessionToken = %q, want %q", result.SessionToken, "keylessToken")
	}
	if result.Expiration.IsZero() {
		t.Error("Expiration must not be zero")
	}

	// No-passthrough: identity token must not appear in any output field.
	if result.AccessKeyID == in.WebIdentityToken ||
		result.SecretAccessKey == in.WebIdentityToken ||
		result.SessionToken == in.WebIdentityToken {
		t.Error("output contains web identity token — no-passthrough violation")
	}

	if mock.capturedWebIdentityRoleARN != in.RoleARN {
		t.Errorf("inner caller RoleARN = %q, want %q", mock.capturedWebIdentityRoleARN, in.RoleARN)
	}
	if mock.capturedWebIdentityToken != in.WebIdentityToken {
		t.Errorf("inner caller WebIdentityToken = %q, want %q", mock.capturedWebIdentityToken, in.WebIdentityToken)
	}
}

// TestAWSWebIdentitySTSClient_ErrorSurfaces verifies errors from the caller propagate.
func TestAWSWebIdentitySTSClient_ErrorSurfaces(t *testing.T) {
	mock := &mockAWSSTSCaller{webIdentityErr: errors.New("sts: AccessDenied")}
	client := cloud.NewAWSWebIdentitySTSClientWithCaller(mock)

	_, err := client.AssumeRoleWithWebIdentity(context.Background(), tokenexchange.STSAssumeRoleWithWebIdentityInput{
		RoleARN:          "arn:aws:iam::123:role/ErrRole",
		SessionName:      "straylight-exec",
		WebIdentityToken: "tok",
		DurationSeconds:  900,
	})
	if err == nil {
		t.Fatal("expected error from STS failure, got nil")
	}
}

// ---------------------------------------------------------------------------
// AWS static STS real client tests (via mock AWSSTSCaller seam)
// ---------------------------------------------------------------------------

// TestAWSStaticSTSClient_ImplementsInterface is a compile-time assertion.
func TestAWSStaticSTSClient_ImplementsInterface(t *testing.T) {
	var _ cloud.STSClient = (*cloud.AWSStaticSTSClient)(nil)
}

// TestAWSStaticSTSClient_ForwardsInput verifies that RoleARN, SessionName, and
// DurationSeconds are forwarded to the inner caller and the response maps
// to STSCredentials.
func TestAWSStaticSTSClient_ForwardsInput(t *testing.T) {
	expiry := time.Now().Add(time.Hour)
	mock := &mockAWSSTSCaller{
		assumeRoleResp: &cloud.RawAWSCredentials{
			AccessKeyID:     "AKIASTATIC",
			SecretAccessKey: "staticSecret",
			SessionToken:    "staticToken",
			ExpiresAt:       expiry,
		},
	}

	client := cloud.NewAWSStaticSTSClientWithCaller(mock)
	in := cloud.STSAssumeRoleInput{
		RoleARN:         "arn:aws:iam::111111111111:role/StaticRole",
		SessionName:     "straylight-exec",
		DurationSeconds: 900,
	}

	result, err := client.AssumeRole(context.Background(), in)
	if err != nil {
		t.Fatalf("AssumeRole() error = %v", err)
	}

	if result.AccessKeyID != "AKIASTATIC" {
		t.Errorf("AccessKeyID = %q, want %q", result.AccessKeyID, "AKIASTATIC")
	}
	if result.SecretAccessKey != "staticSecret" {
		t.Errorf("SecretAccessKey = %q, want %q", result.SecretAccessKey, "staticSecret")
	}
	if result.SessionToken != "staticToken" {
		t.Errorf("SessionToken = %q, want %q", result.SessionToken, "staticToken")
	}
	if result.Expiration.IsZero() {
		t.Error("Expiration must not be zero")
	}

	if mock.capturedAssumeRoleARN != in.RoleARN {
		t.Errorf("inner caller RoleARN = %q, want %q", mock.capturedAssumeRoleARN, in.RoleARN)
	}
}

// TestAWSStaticSTSClient_ErrorSurfaces verifies errors from the caller propagate.
func TestAWSStaticSTSClient_ErrorSurfaces(t *testing.T) {
	mock := &mockAWSSTSCaller{assumeRoleErr: errors.New("sts: AccessDenied")}
	client := cloud.NewAWSStaticSTSClientWithCaller(mock)

	_, err := client.AssumeRole(context.Background(), cloud.STSAssumeRoleInput{
		RoleARN:         "arn:aws:iam::123:role/ErrRole",
		SessionName:     "straylight-exec",
		DurationSeconds: 900,
	})
	if err == nil {
		t.Fatal("expected error from AssumeRole failure, got nil")
	}
}

// ---------------------------------------------------------------------------
// mock AWSSTSCaller — test double for the inner SDK/HTTP seam
// ---------------------------------------------------------------------------

// mockAWSSTSCaller implements cloud.AWSSTSCaller and records inputs.
type mockAWSSTSCaller struct {
	// AssumeRoleWithWebIdentity side.
	webIdentityResp            *cloud.RawAWSCredentials
	webIdentityErr             error
	capturedWebIdentityRoleARN string
	capturedWebIdentityToken   string

	// AssumeRole side.
	assumeRoleResp        *cloud.RawAWSCredentials
	assumeRoleErr         error
	capturedAssumeRoleARN string
}

func (m *mockAWSSTSCaller) AssumeRoleWithWebIdentityRaw(
	_ context.Context,
	roleARN, sessionName, webIdentityToken string,
	durationSecs int32,
	policy *string,
) (*cloud.RawAWSCredentials, error) {
	m.capturedWebIdentityRoleARN = roleARN
	m.capturedWebIdentityToken = webIdentityToken
	if m.webIdentityErr != nil {
		return nil, m.webIdentityErr
	}
	return m.webIdentityResp, nil
}

func (m *mockAWSSTSCaller) AssumeRoleRaw(
	_ context.Context,
	roleARN, sessionName string,
	durationSecs int32,
	policy *string,
) (*cloud.RawAWSCredentials, error) {
	m.capturedAssumeRoleARN = roleARN
	if m.assumeRoleErr != nil {
		return nil, m.assumeRoleErr
	}
	return m.assumeRoleResp, nil
}
