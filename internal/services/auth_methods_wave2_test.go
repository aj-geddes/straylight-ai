// Package services_test — failing RED tests for Wave 2 validation additions.
// Tests for custom_auth, aws_sigv4, hmac_signature ValidateAuthMethod cases.
package services_test

import (
	"testing"

	"github.com/straylight-ai/straylight/internal/services"
)

// ---------------------------------------------------------------------------
// InjectionCustomAuth
// ---------------------------------------------------------------------------

func TestValidateAuthMethod_AcceptsCustomAuthWithHeaders(t *testing.T) {
	am := services.AuthMethod{
		ID:   "dual_key",
		Name: "Dual Key Auth",
		Fields: []services.CredentialField{
			{Key: "api_key", Label: "API Key", Type: services.FieldPassword, Required: true},
			{Key: "client_id", Label: "Client ID", Type: services.FieldText, Required: true},
		},
		Injection: services.InjectionConfig{
			Type: services.InjectionCustomAuth,
			Custom: &services.CustomAuthSpec{
				Headers: map[string]string{
					"X-Api-Key":   "{{.api_key}}",
					"X-Client-Id": "{{.client_id}}",
				},
			},
		},
	}
	if err := services.ValidateAuthMethod(am); err != nil {
		t.Errorf("ValidateAuthMethod() returned unexpected error: %v", err)
	}
}

func TestValidateAuthMethod_AcceptsCustomAuthWithQuery(t *testing.T) {
	am := services.AuthMethod{
		ID:   "query_auth",
		Name: "Query Auth",
		Fields: []services.CredentialField{
			{Key: "token", Label: "Token", Type: services.FieldPassword, Required: true},
		},
		Injection: services.InjectionConfig{
			Type: services.InjectionCustomAuth,
			Custom: &services.CustomAuthSpec{
				Query: map[string]string{
					"api_key": "{{.token}}",
				},
			},
		},
	}
	if err := services.ValidateAuthMethod(am); err != nil {
		t.Errorf("ValidateAuthMethod() returned unexpected error: %v", err)
	}
}

func TestValidateAuthMethod_AcceptsCustomAuthWithBody(t *testing.T) {
	am := services.AuthMethod{
		ID:   "body_auth",
		Name: "Body Auth",
		Fields: []services.CredentialField{
			{Key: "client_id", Label: "Client ID", Type: services.FieldText, Required: true},
			{Key: "client_secret", Label: "Client Secret", Type: services.FieldPassword, Required: true},
		},
		Injection: services.InjectionConfig{
			Type: services.InjectionCustomAuth,
			Custom: &services.CustomAuthSpec{
				Body: map[string]string{
					"client_id":     "{{.client_id}}",
					"client_secret": "{{.client_secret}}",
					"grant_type":    "client_credentials",
				},
				BodyMode: "json",
			},
		},
	}
	if err := services.ValidateAuthMethod(am); err != nil {
		t.Errorf("ValidateAuthMethod() returned unexpected error: %v", err)
	}
}

func TestValidateAuthMethod_RejectsCustomAuthWithNilCustom(t *testing.T) {
	am := services.AuthMethod{
		ID:   "bad_custom",
		Name: "Bad Custom",
		Fields: []services.CredentialField{
			{Key: "token", Label: "Token", Type: services.FieldPassword, Required: true},
		},
		Injection: services.InjectionConfig{
			Type:   services.InjectionCustomAuth,
			Custom: nil,
		},
	}
	if err := services.ValidateAuthMethod(am); err == nil {
		t.Error("ValidateAuthMethod() expected error for custom_auth with nil Custom, got nil")
	}
}

func TestValidateAuthMethod_RejectsCustomAuthWithEmptyCustom(t *testing.T) {
	am := services.AuthMethod{
		ID:   "empty_custom",
		Name: "Empty Custom",
		Fields: []services.CredentialField{
			{Key: "token", Label: "Token", Type: services.FieldPassword, Required: true},
		},
		Injection: services.InjectionConfig{
			Type:   services.InjectionCustomAuth,
			Custom: &services.CustomAuthSpec{}, // no headers, query, or body
		},
	}
	if err := services.ValidateAuthMethod(am); err == nil {
		t.Error("ValidateAuthMethod() expected error for custom_auth with empty Custom (no headers/query/body), got nil")
	}
}

func TestValidateAuthMethod_RejectsCustomAuthWithInvalidBodyMode(t *testing.T) {
	am := services.AuthMethod{
		ID:   "bad_body_mode",
		Name: "Bad Body Mode",
		Fields: []services.CredentialField{
			{Key: "token", Label: "Token", Type: services.FieldPassword, Required: true},
		},
		Injection: services.InjectionConfig{
			Type: services.InjectionCustomAuth,
			Custom: &services.CustomAuthSpec{
				Body: map[string]string{
					"key": "{{.token}}",
				},
				BodyMode: "xml", // invalid
			},
		},
	}
	if err := services.ValidateAuthMethod(am); err == nil {
		t.Error("ValidateAuthMethod() expected error for invalid body_mode 'xml', got nil")
	}
}

// ---------------------------------------------------------------------------
// InjectionAWSSigV4
// ---------------------------------------------------------------------------

func TestValidateAuthMethod_AcceptsAWSSigV4WithSignSpec(t *testing.T) {
	am := services.AuthMethod{
		ID:   "aws_key",
		Name: "AWS SigV4",
		Fields: []services.CredentialField{
			{Key: "access_key_id", Label: "Access Key ID", Type: services.FieldText, Required: true},
			{Key: "secret_access_key", Label: "Secret Access Key", Type: services.FieldPassword, Required: true},
		},
		Injection: services.InjectionConfig{
			Type: services.InjectionAWSSigV4,
			Sign: &services.SignSpec{
				AWS: &services.AWSSignSpec{
					Region:  "us-east-1",
					Service: "s3",
				},
			},
		},
	}
	if err := services.ValidateAuthMethod(am); err != nil {
		t.Errorf("ValidateAuthMethod() returned unexpected error: %v", err)
	}
}

func TestValidateAuthMethod_RejectsAWSSigV4WithNilSign(t *testing.T) {
	am := services.AuthMethod{
		ID:   "aws_no_sign",
		Name: "AWS No Sign",
		Fields: []services.CredentialField{
			{Key: "access_key_id", Label: "Access Key ID", Type: services.FieldText, Required: true},
			{Key: "secret_access_key", Label: "Secret Key", Type: services.FieldPassword, Required: true},
		},
		Injection: services.InjectionConfig{
			Type: services.InjectionAWSSigV4,
			Sign: nil,
		},
	}
	if err := services.ValidateAuthMethod(am); err == nil {
		t.Error("ValidateAuthMethod() expected error for aws_sigv4 with nil Sign, got nil")
	}
}

func TestValidateAuthMethod_RejectsAWSSigV4WithEmptyService(t *testing.T) {
	am := services.AuthMethod{
		ID:   "aws_no_service",
		Name: "AWS No Service",
		Fields: []services.CredentialField{
			{Key: "access_key_id", Label: "Access Key ID", Type: services.FieldText, Required: true},
			{Key: "secret_access_key", Label: "Secret Key", Type: services.FieldPassword, Required: true},
		},
		Injection: services.InjectionConfig{
			Type: services.InjectionAWSSigV4,
			Sign: &services.SignSpec{
				AWS: &services.AWSSignSpec{
					Region:  "us-east-1",
					Service: "", // missing
				},
			},
		},
	}
	if err := services.ValidateAuthMethod(am); err == nil {
		t.Error("ValidateAuthMethod() expected error for aws_sigv4 with empty Service, got nil")
	}
}

// ---------------------------------------------------------------------------
// InjectionHMACSignature
// ---------------------------------------------------------------------------

func TestValidateAuthMethod_AcceptsHMACSignatureWithFullSpec(t *testing.T) {
	am := services.AuthMethod{
		ID:   "hmac_auth",
		Name: "HMAC Signature",
		Fields: []services.CredentialField{
			{Key: "webhook_secret", Label: "Webhook Secret", Type: services.FieldPassword, Required: true},
		},
		Injection: services.InjectionConfig{
			Type: services.InjectionHMACSignature,
			Sign: &services.SignSpec{
				HMAC: &services.HMACSpec{
					Algorithm:    "sha256",
					Encoding:     "hex",
					HeaderName:   "X-Hub-Signature-256",
					HeaderPrefix: "sha256=",
					SecretField:  "webhook_secret",
					SignedString: "{{.body}}",
				},
			},
		},
	}
	if err := services.ValidateAuthMethod(am); err != nil {
		t.Errorf("ValidateAuthMethod() returned unexpected error: %v", err)
	}
}

func TestValidateAuthMethod_RejectsHMACSignatureWithNilSign(t *testing.T) {
	am := services.AuthMethod{
		ID:   "hmac_no_sign",
		Name: "HMAC No Sign",
		Fields: []services.CredentialField{
			{Key: "secret", Label: "Secret", Type: services.FieldPassword, Required: true},
		},
		Injection: services.InjectionConfig{
			Type: services.InjectionHMACSignature,
			Sign: nil,
		},
	}
	if err := services.ValidateAuthMethod(am); err == nil {
		t.Error("ValidateAuthMethod() expected error for hmac_signature with nil Sign, got nil")
	}
}

func TestValidateAuthMethod_RejectsHMACSignatureWithEmptyAlgorithm(t *testing.T) {
	am := services.AuthMethod{
		ID:   "hmac_no_alg",
		Name: "HMAC No Algorithm",
		Fields: []services.CredentialField{
			{Key: "secret", Label: "Secret", Type: services.FieldPassword, Required: true},
		},
		Injection: services.InjectionConfig{
			Type: services.InjectionHMACSignature,
			Sign: &services.SignSpec{
				HMAC: &services.HMACSpec{
					Algorithm:    "",
					Encoding:     "hex",
					HeaderName:   "X-Sig",
					SecretField:  "secret",
					SignedString: "{{.body}}",
				},
			},
		},
	}
	if err := services.ValidateAuthMethod(am); err == nil {
		t.Error("ValidateAuthMethod() expected error for hmac_signature with empty Algorithm, got nil")
	}
}

func TestValidateAuthMethod_RejectsHMACSignatureWithEmptyHeaderName(t *testing.T) {
	am := services.AuthMethod{
		ID:   "hmac_no_header",
		Name: "HMAC No Header",
		Fields: []services.CredentialField{
			{Key: "secret", Label: "Secret", Type: services.FieldPassword, Required: true},
		},
		Injection: services.InjectionConfig{
			Type: services.InjectionHMACSignature,
			Sign: &services.SignSpec{
				HMAC: &services.HMACSpec{
					Algorithm:    "sha256",
					Encoding:     "hex",
					HeaderName:   "",
					SecretField:  "secret",
					SignedString: "{{.body}}",
				},
			},
		},
	}
	if err := services.ValidateAuthMethod(am); err == nil {
		t.Error("ValidateAuthMethod() expected error for hmac_signature with empty HeaderName, got nil")
	}
}

func TestValidateAuthMethod_RejectsHMACSignatureWithEmptySecretField(t *testing.T) {
	am := services.AuthMethod{
		ID:   "hmac_no_secret",
		Name: "HMAC No SecretField",
		Fields: []services.CredentialField{
			{Key: "secret", Label: "Secret", Type: services.FieldPassword, Required: true},
		},
		Injection: services.InjectionConfig{
			Type: services.InjectionHMACSignature,
			Sign: &services.SignSpec{
				HMAC: &services.HMACSpec{
					Algorithm:    "sha256",
					Encoding:     "hex",
					HeaderName:   "X-Sig",
					SecretField:  "",
					SignedString: "{{.body}}",
				},
			},
		},
	}
	if err := services.ValidateAuthMethod(am); err == nil {
		t.Error("ValidateAuthMethod() expected error for hmac_signature with empty SecretField, got nil")
	}
}

func TestValidateAuthMethod_RejectsHMACSignatureWithEmptySignedString(t *testing.T) {
	am := services.AuthMethod{
		ID:   "hmac_no_signed",
		Name: "HMAC No SignedString",
		Fields: []services.CredentialField{
			{Key: "secret", Label: "Secret", Type: services.FieldPassword, Required: true},
		},
		Injection: services.InjectionConfig{
			Type: services.InjectionHMACSignature,
			Sign: &services.SignSpec{
				HMAC: &services.HMACSpec{
					Algorithm:    "sha256",
					Encoding:     "hex",
					HeaderName:   "X-Sig",
					SecretField:  "secret",
					SignedString: "",
				},
			},
		},
	}
	if err := services.ValidateAuthMethod(am); err == nil {
		t.Error("ValidateAuthMethod() expected error for hmac_signature with empty SignedString, got nil")
	}
}

// ---------------------------------------------------------------------------
// New InjectionType constants exist
// ---------------------------------------------------------------------------

func TestInjectionTypeConstants_Wave2Defined(t *testing.T) {
	types := []services.InjectionType{
		services.InjectionCustomAuth,
		services.InjectionAWSSigV4,
		services.InjectionHMACSignature,
	}
	for _, it := range types {
		if it == "" {
			t.Errorf("expected non-empty InjectionType constant for Wave-2 type %q", it)
		}
	}
	if services.InjectionCustomAuth != "custom_auth" {
		t.Errorf("InjectionCustomAuth = %q, want 'custom_auth'", services.InjectionCustomAuth)
	}
	if services.InjectionAWSSigV4 != "aws_sigv4" {
		t.Errorf("InjectionAWSSigV4 = %q, want 'aws_sigv4'", services.InjectionAWSSigV4)
	}
	if services.InjectionHMACSignature != "hmac_signature" {
		t.Errorf("InjectionHMACSignature = %q, want 'hmac_signature'", services.InjectionHMACSignature)
	}
}
