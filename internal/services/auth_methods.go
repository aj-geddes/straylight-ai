// Package services — auth method types and validation.
package services

import (
	"fmt"
	"regexp"
)

// compiledPatterns caches pre-compiled regexp objects for each unique Field.Pattern
// string found in ServiceTemplates. Populated at package init time so that any
// invalid pattern causes a startup panic rather than a runtime error.
var compiledPatterns map[string]*regexp.Regexp

// init pre-compiles all CredentialField patterns defined in ServiceTemplates.
// Panics at startup if any pattern is syntactically invalid, making misconfiguration
// visible at deployment time rather than during user credential submission.
func init() {
	compiledPatterns = make(map[string]*regexp.Regexp)
	for i := range ServiceTemplates {
		for j := range ServiceTemplates[i].AuthMethods {
			for k := range ServiceTemplates[i].AuthMethods[j].Fields {
				p := ServiceTemplates[i].AuthMethods[j].Fields[k].Pattern
				if p != "" {
					if _, seen := compiledPatterns[p]; !seen {
						compiledPatterns[p] = regexp.MustCompile(p)
					}
				}
			}
		}
	}
}

// ValidateCredentialFields checks that all required fields defined in am are
// present in credentials, and that provided values match their defined regex
// pattern. Uses pre-compiled patterns from compiledPatterns for efficiency.
func ValidateCredentialFields(am *AuthMethod, credentials map[string]string) error {
	for _, field := range am.Fields {
		val, present := credentials[field.Key]
		if field.Required && !present {
			return fmt.Errorf("credential field %q is required", field.Key)
		}
		if present && field.Pattern != "" {
			re, ok := compiledPatterns[field.Pattern]
			if !ok {
				// Pattern not in compiledPatterns — compile on demand (should not
				// occur for ServiceTemplates patterns, but handles dynamic auth methods).
				var err error
				re, err = regexp.Compile(field.Pattern)
				if err != nil {
					return fmt.Errorf("credential field %q has invalid pattern: %w", field.Key, err)
				}
			}
			if !re.MatchString(val) {
				return fmt.Errorf("credential field %q does not match required pattern", field.Key)
			}
		}
	}
	return nil
}

// authMethodIDPattern matches valid auth method IDs: starts with lowercase letter,
// followed by up to 62 lowercase alphanumeric or underscore characters.
var authMethodIDPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,62}$`)

// reservedFieldKeys are field keys that are reserved for internal metadata.
var reservedFieldKeys = map[string]bool{
	"auth_method": true,
	"type":        true,
}

// validInjectionTypes is the set of accepted injection type strings.
var validInjectionTypes = map[InjectionType]bool{
	InjectionBearerHeader:  true,
	InjectionCustomHeader:  true,
	InjectionMultiHeader:   true,
	InjectionQueryParam:    true,
	InjectionBasicAuth:     true,
	InjectionOAuth:         true,
	InjectionNamedStrategy: true,
}

// InjectionType enumerates the supported credential injection strategies.
type InjectionType string

const (
	InjectionBearerHeader  InjectionType = "bearer_header"
	InjectionCustomHeader  InjectionType = "custom_header"
	InjectionMultiHeader   InjectionType = "multi_header"
	InjectionQueryParam    InjectionType = "query_param"
	InjectionBasicAuth     InjectionType = "basic_auth"
	InjectionOAuth         InjectionType = "oauth"
	InjectionNamedStrategy InjectionType = "named_strategy"
)

// FieldType enumerates the UI input types for credential fields.
type FieldType string

const (
	FieldPassword FieldType = "password"
	FieldText     FieldType = "text"
	FieldTextarea FieldType = "textarea"
)

// AuthMethod describes one way to authenticate with a service.
// Templates define a slice of these; the user chooses one when creating a service.
type AuthMethod struct {
	ID          string            `json:"id"                     yaml:"id"`
	Name        string            `json:"name"                   yaml:"name"`
	Description string            `json:"description,omitempty"  yaml:"description,omitempty"`
	Fields      []CredentialField `json:"fields"                 yaml:"fields"`
	Injection   InjectionConfig   `json:"injection"              yaml:"injection"`
	AutoRefresh bool              `json:"auto_refresh,omitempty" yaml:"auto_refresh,omitempty"`
	TokenPrefix string            `json:"token_prefix,omitempty" yaml:"token_prefix,omitempty"`
	// KeyURL is an optional URL where the user can obtain or manage the credential.
	// Displayed as a "Where do I get this?" link in the credential form.
	KeyURL      string            `json:"key_url,omitempty"      yaml:"key_url,omitempty"`
}

// CredentialField describes one input the user must provide for an auth method.
type CredentialField struct {
	Key         string    `json:"key"                   yaml:"key"`
	Label       string    `json:"label"                 yaml:"label"`
	Type        FieldType `json:"type"                  yaml:"type"`
	Placeholder string    `json:"placeholder,omitempty" yaml:"placeholder,omitempty"`
	Required    bool      `json:"required"              yaml:"required"`
	Pattern     string    `json:"pattern,omitempty"     yaml:"pattern,omitempty"`
	HelpText    string    `json:"help_text,omitempty"   yaml:"help_text,omitempty"`
}

// InjectionConfig describes how credentials are injected into HTTP requests.
type InjectionConfig struct {
	Type           InjectionType     `json:"type"                      yaml:"type"`
	HeaderName     string            `json:"header_name,omitempty"     yaml:"header_name,omitempty"`
	HeaderTemplate string            `json:"header_template,omitempty" yaml:"header_template,omitempty"`
	QueryParam     string            `json:"query_param,omitempty"     yaml:"query_param,omitempty"`
	Headers        map[string]string `json:"headers,omitempty"         yaml:"headers,omitempty"`
	Strategy       string            `json:"strategy,omitempty"        yaml:"strategy,omitempty"`
}

// ServiceTemplate is a pre-configured template for a common service.
// Templates are read-only and define the available auth methods.
type ServiceTemplate struct {
	ID             string            `json:"id"                        yaml:"id"`
	DisplayName    string            `json:"display_name"              yaml:"display_name"`
	Description    string            `json:"description,omitempty"     yaml:"description,omitempty"`
	Icon           string            `json:"icon,omitempty"            yaml:"icon,omitempty"`
	Target         string            `json:"target"                    yaml:"target"`
	DefaultHeaders map[string]string `json:"default_headers,omitempty" yaml:"default_headers,omitempty"`
	AuthMethods    []AuthMethod      `json:"auth_methods"              yaml:"auth_methods"`
	ExecConfig     *ExecConfig       `json:"exec_config,omitempty"     yaml:"exec_config,omitempty"`
}

// ExecConfig holds configuration for credential injection into command execution.
type ExecConfig struct {
	EnvVar string `json:"env_var" yaml:"env_var"`
}

// ValidateAuthMethod checks that am is a well-formed authentication method.
// It enforces:
//   - ID is non-empty and matches ^[a-z][a-z0-9_]{0,62}$
//   - Name is non-empty
//   - Field keys are unique within the auth method
//   - No field key is a reserved metadata key (auth_method, type)
//   - Injection type is a valid enum value
//   - custom_header requires HeaderName
//   - query_param requires QueryParam
//   - named_strategy requires Strategy
//   - oauth requires empty Fields slice
func ValidateAuthMethod(am AuthMethod) error {
	if !authMethodIDPattern.MatchString(am.ID) {
		return fmt.Errorf("auth method: invalid id %q: must match ^[a-z][a-z0-9_]{0,62}$", am.ID)
	}

	if am.Name == "" {
		return fmt.Errorf("auth method %q: name is required", am.ID)
	}

	// Check field keys for uniqueness and reserved keys.
	seen := make(map[string]bool, len(am.Fields))
	for _, f := range am.Fields {
		if reservedFieldKeys[f.Key] {
			return fmt.Errorf("auth method %q: field key %q is reserved", am.ID, f.Key)
		}
		if seen[f.Key] {
			return fmt.Errorf("auth method %q: duplicate field key %q", am.ID, f.Key)
		}
		seen[f.Key] = true
	}

	// Validate injection type.
	if !validInjectionTypes[am.Injection.Type] {
		return fmt.Errorf("auth method %q: invalid injection type %q", am.ID, am.Injection.Type)
	}

	// Type-specific injection validation.
	switch am.Injection.Type {
	case InjectionCustomHeader:
		if am.Injection.HeaderName == "" {
			return fmt.Errorf("auth method %q: custom_header injection requires header_name", am.ID)
		}
	case InjectionQueryParam:
		if am.Injection.QueryParam == "" {
			return fmt.Errorf("auth method %q: query_param injection requires query_param", am.ID)
		}
	case InjectionNamedStrategy:
		if am.Injection.Strategy == "" {
			return fmt.Errorf("auth method %q: named_strategy injection requires strategy", am.ID)
		}
	case InjectionOAuth:
		if len(am.Fields) != 0 {
			return fmt.Errorf("auth method %q: oauth injection must have empty fields slice", am.ID)
		}
	}

	return nil
}

// ValidateTemplate checks that t is a well-formed service template.
// It enforces:
//   - At least one auth method
//   - Auth method IDs are unique within the template
//   - All auth methods pass ValidateAuthMethod
func ValidateTemplate(t ServiceTemplate) error {
	if len(t.AuthMethods) == 0 {
		return fmt.Errorf("template %q: must have at least one auth method", t.ID)
	}

	seen := make(map[string]bool, len(t.AuthMethods))
	for _, am := range t.AuthMethods {
		if seen[am.ID] {
			return fmt.Errorf("template %q: duplicate auth method id %q", t.ID, am.ID)
		}
		seen[am.ID] = true

		if err := ValidateAuthMethod(am); err != nil {
			return fmt.Errorf("template %q: %w", t.ID, err)
		}
	}

	return nil
}

// FilterTemplatesForPersonalTier removes OAuth and named-strategy auth methods
// from templates, returning only paste-key methods suitable for personal use.
// Exception: named_strategy with strategy="ssh_key" is allowed for SSH key storage.
// Templates that have no remaining auth methods after filtering are excluded
// entirely. The input slice is not modified.
func FilterTemplatesForPersonalTier(templates []ServiceTemplate) []ServiceTemplate {
	var result []ServiceTemplate
	for _, tmpl := range templates {
		filtered := tmpl
		var methods []AuthMethod
		for _, am := range tmpl.AuthMethods {
			// Skip OAuth methods — they are enterprise features.
			if am.Injection.Type == InjectionOAuth {
				continue
			}
			// Allow SSH key and database connection storage in personal tier.
			if am.Injection.Type == InjectionNamedStrategy {
				switch am.Injection.Strategy {
				case "ssh_key", "connection_string":
					methods = append(methods, am)
					continue
				}
			}
			// Skip other named strategies — they are not implemented for personal tier.
			if am.Injection.Type == InjectionNamedStrategy {
				continue
			}
			methods = append(methods, am)
		}
		if len(methods) > 0 {
			filtered.AuthMethods = methods
			result = append(result, filtered)
		}
	}
	return result
}

// ServiceTemplates is the built-in catalog of pre-configured service templates.
// Each template defines one or more auth methods the user can choose from when
// creating a service. Templates are read-only.
var ServiceTemplates = []ServiceTemplate{
	{
		ID:          "github",
		DisplayName: "GitHub",
		Description: "GitHub REST and GraphQL API",
		Icon:        "github",
		Target:      "https://api.github.com",
		DefaultHeaders: map[string]string{
			"Accept":               "application/vnd.github+json",
			"X-GitHub-Api-Version": "2022-11-28",
		},
		ExecConfig: &ExecConfig{EnvVar: "GH_TOKEN"},
		AuthMethods: []AuthMethod{
			{
				ID:          "github_pat_classic",
				Name:        "Personal Access Token (classic)",
				Description: "Classic GitHub PAT with broad repository access",
				TokenPrefix: "ghp_",
				KeyURL:      "https://github.com/settings/tokens",
				Fields: []CredentialField{
					{
						Key:         "token",
						Label:       "Personal Access Token",
						Type:        FieldPassword,
						Placeholder: "ghp_xxxxxxxxxxxx",
						Required:    true,
						Pattern:     `^(ghp_|gho_|ghu_|ghs_|ghr_|github_pat_)[a-zA-Z0-9_]{20,}$`,
						HelpText:    "Accepts classic PATs (ghp_), OAuth tokens (gho_), and other GitHub token formats",
					},
				},
				Injection: InjectionConfig{Type: InjectionBearerHeader},
			},
			{
				ID:          "github_fine_grained_pat",
				Name:        "Fine-grained PAT",
				Description: "Scoped token with granular repository and permission control",
				TokenPrefix: "github_pat_",
				KeyURL:      "https://github.com/settings/tokens",
				Fields: []CredentialField{
					{
						Key:         "token",
						Label:       "Fine-grained Personal Access Token",
						Type:        FieldPassword,
						Placeholder: "github_pat_xxxxxxxxxxxx",
						Required:    true,
						Pattern:     `^github_pat_`,
					},
				},
				Injection: InjectionConfig{Type: InjectionBearerHeader},
			},
			{
				ID:          "github_app",
				Name:        "GitHub App",
				Description: "Authenticate as a GitHub App installation (auto-generates JWT)",
				AutoRefresh: true,
				Fields: []CredentialField{
					{Key: "app_id", Label: "App ID", Type: FieldText, Placeholder: "12345", Required: true, Pattern: `^[0-9]+$`},
					{Key: "installation_id", Label: "Installation ID", Type: FieldText, Placeholder: "67890", Required: true, Pattern: `^[0-9]+$`},
					{Key: "private_key", Label: "Private Key (PEM)", Type: FieldTextarea, Placeholder: "-----BEGIN RSA PRIVATE KEY-----\n...", Required: true},
				},
				Injection: InjectionConfig{Type: InjectionNamedStrategy, Strategy: "github_app_jwt"},
			},
			{
				ID:          "github_oauth",
				Name:        "OAuth",
				Description: "Browser-based GitHub OAuth authorization",
				Fields:      []CredentialField{},
				Injection:   InjectionConfig{Type: InjectionOAuth},
			},
		},
	},
	{
		ID:          "stripe",
		DisplayName: "Stripe",
		Description: "Stripe payment processing API",
		Icon:        "stripe",
		Target:      "https://api.stripe.com",
		DefaultHeaders: map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
		},
		AuthMethods: []AuthMethod{
			{
				ID:          "stripe_api_key",
				Name:        "API Key",
				Description: "Standard Stripe secret key",
				KeyURL:      "https://dashboard.stripe.com/apikeys",
				Fields: []CredentialField{
					{Key: "token", Label: "Secret Key", Type: FieldPassword, Placeholder: "sk_test_xxxxxxxxxxxx", Required: true, Pattern: `^sk_(test|live)_`},
				},
				Injection: InjectionConfig{Type: InjectionBearerHeader},
			},
			{
				ID:          "stripe_restricted_key",
				Name:        "Restricted Key",
				Description: "Stripe restricted API key with limited permissions",
				KeyURL:      "https://dashboard.stripe.com/apikeys",
				Fields: []CredentialField{
					{Key: "token", Label: "Restricted Key", Type: FieldPassword, Placeholder: "rk_test_xxxxxxxxxxxx", Required: true, Pattern: `^rk_(test|live)_`},
				},
				Injection: InjectionConfig{Type: InjectionBearerHeader},
			},
			{
				ID:          "stripe_connect_oauth",
				Name:        "Stripe Connect OAuth",
				Description: "Browser-based Stripe Connect authorization",
				Fields:      []CredentialField{},
				Injection:   InjectionConfig{Type: InjectionOAuth},
			},
		},
	},
	{
		ID:          "openai",
		DisplayName: "OpenAI",
		Description: "OpenAI API (GPT, DALL-E, Whisper, etc.)",
		Icon:        "openai",
		Target:      "https://api.openai.com",
		DefaultHeaders: map[string]string{
			"Content-Type": "application/json",
		},
		AuthMethods: []AuthMethod{
			{
				ID:          "openai_api_key",
				Name:        "API Key",
				Description: "Standard OpenAI API key",
				KeyURL:      "https://platform.openai.com/api-keys",
				Fields: []CredentialField{
					{Key: "token", Label: "API Key", Type: FieldPassword, Placeholder: "sk-xxxxxxxxxxxx", Required: true, Pattern: `^sk-`},
				},
				Injection: InjectionConfig{Type: InjectionBearerHeader},
			},
			{
				ID:          "openai_project_key",
				Name:        "Project API Key",
				Description: "Project-scoped OpenAI API key",
				KeyURL:      "https://platform.openai.com/api-keys",
				Fields: []CredentialField{
					{Key: "token", Label: "Project API Key", Type: FieldPassword, Placeholder: "sk-proj-xxxxxxxxxxxx", Required: true, Pattern: `^sk-proj-`},
				},
				Injection: InjectionConfig{Type: InjectionBearerHeader},
			},
		},
	},
	{
		ID:          "anthropic",
		DisplayName: "Anthropic",
		Description: "Anthropic Claude API",
		Icon:        "anthropic",
		Target:      "https://api.anthropic.com",
		DefaultHeaders: map[string]string{
			"Content-Type": "application/json",
		},
		AuthMethods: []AuthMethod{
			{
				ID:          "anthropic_api_key",
				Name:        "API Key",
				Description: "Anthropic API key (injected as x-api-key header)",
				KeyURL:      "https://console.anthropic.com/settings/keys",
				Fields: []CredentialField{
					{Key: "token", Label: "API Key", Type: FieldPassword, Placeholder: "sk-ant-xxxxxxxxxxxx", Required: true, Pattern: `^sk-ant-`},
				},
				Injection: InjectionConfig{
					Type:           InjectionCustomHeader,
					HeaderName:     "x-api-key",
					HeaderTemplate: "{{.Secret}}",
				},
			},
		},
	},
	{
		ID:          "slack",
		DisplayName: "Slack",
		Description: "Slack Web API",
		Icon:        "slack",
		Target:      "https://slack.com/api",
		AuthMethods: []AuthMethod{
			{
				ID:          "slack_bot_token",
				Name:        "Bot Token",
				Description: "Slack bot user OAuth token",
				KeyURL:      "https://api.slack.com/apps",
				Fields: []CredentialField{
					{Key: "token", Label: "Bot Token", Type: FieldPassword, Placeholder: "xoxb-xxxxxxxxxxxx", Required: true, Pattern: `^xoxb-`},
				},
				Injection: InjectionConfig{Type: InjectionBearerHeader},
			},
			{
				ID:          "slack_user_token",
				Name:        "User Token",
				Description: "Slack user OAuth token",
				Fields: []CredentialField{
					{Key: "token", Label: "User Token", Type: FieldPassword, Placeholder: "xoxp-xxxxxxxxxxxx", Required: true, Pattern: `^xoxp-`},
				},
				Injection: InjectionConfig{Type: InjectionBearerHeader},
			},
		},
	},
	{
		ID:          "gitlab",
		DisplayName: "GitLab",
		Description: "GitLab REST API",
		Icon:        "gitlab",
		Target:      "https://gitlab.com/api/v4",
		AuthMethods: []AuthMethod{
			{
				ID:          "gitlab_pat",
				Name:        "Personal Access Token",
				Description: "GitLab personal access token",
				KeyURL:      "https://gitlab.com/-/user_settings/personal_access_tokens",
				Fields: []CredentialField{
					{Key: "token", Label: "Personal Access Token", Type: FieldPassword, Placeholder: "glpat-xxxxxxxxxxxx", Required: true},
				},
				Injection: InjectionConfig{
					Type:       InjectionCustomHeader,
					HeaderName: "PRIVATE-TOKEN",
				},
			},
			{
				ID:          "gitlab_oauth",
				Name:        "OAuth",
				Description: "Browser-based GitLab OAuth authorization",
				Fields:      []CredentialField{},
				Injection:   InjectionConfig{Type: InjectionOAuth},
			},
		},
	},
	{
		ID:          "google",
		DisplayName: "Google",
		Description: "Google APIs (Cloud, Workspace, Maps, etc.)",
		Icon:        "google",
		Target:      "https://www.googleapis.com",
		AuthMethods: []AuthMethod{
			{
				ID:          "google_service_account",
				Name:        "Service Account JSON",
				Description: "Google Cloud service account credentials (JSON key file)",
				AutoRefresh: true,
				Fields: []CredentialField{
					{
						Key:         "service_account_json",
						Label:       "Service Account JSON",
						Type:        FieldTextarea,
						Placeholder: `{"type": "service_account", "project_id": "..."}`,
						Required:    true,
						HelpText:    "Paste the contents of your service account JSON key file",
					},
				},
				Injection: InjectionConfig{
					Type:     InjectionNamedStrategy,
					Strategy: "google_sa",
				},
			},
			{
				ID:          "google_api_key",
				Name:        "API Key",
				Description: "Simple API key (sent as ?key= query parameter)",
				KeyURL:      "https://console.cloud.google.com/apis/credentials",
				Fields: []CredentialField{
					{Key: "token", Label: "API Key", Type: FieldPassword, Placeholder: "AIzaSyXXXXXXXXXXXXXXXXXXXXXXXX", Required: true},
				},
				Injection: InjectionConfig{
					Type:       InjectionQueryParam,
					QueryParam: "key",
				},
			},
			{
				ID:          "google_oauth",
				Name:        "OAuth",
				Description: "Browser-based Google OAuth authorization",
				AutoRefresh: true,
				Fields:      []CredentialField{},
				Injection:   InjectionConfig{Type: InjectionOAuth},
			},
		},
	},
	{
		ID:          "microsoft",
		DisplayName: "Microsoft",
		Description: "Microsoft 365, Azure, Outlook, OneDrive APIs",
		Icon:        "microsoft",
		Target:      "https://graph.microsoft.com",
		DefaultHeaders: map[string]string{
			"Content-Type": "application/json",
		},
		AuthMethods: []AuthMethod{
			{
				ID:          "microsoft_oauth",
				Name:        "OAuth",
				Description: "Browser-based Microsoft OAuth authorization",
				Fields:      []CredentialField{},
				Injection:   InjectionConfig{Type: InjectionOAuth},
				AutoRefresh: true,
			},
		},
	},
	{
		ID:          "aws",
		DisplayName: "AWS",
		Description: "Amazon Web Services APIs",
		Icon:        "aws",
		Target:      "https://amazonaws.com",
		AuthMethods: []AuthMethod{
			{
				ID:          "aws_access_key",
				Name:        "Access Key + Secret Key",
				Description: "IAM user access key pair",
				Fields: []CredentialField{
					{Key: "access_key_id", Label: "Access Key ID", Type: FieldText, Placeholder: "AKIAIOSFODNN7EXAMPLE", Required: true, Pattern: `^AKIA[0-9A-Z]{16}$`},
					{Key: "secret_access_key", Label: "Secret Access Key", Type: FieldPassword, Placeholder: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", Required: true},
				},
				Injection: InjectionConfig{Type: InjectionNamedStrategy, Strategy: "aws_sigv4"},
			},
			{
				ID:          "aws_session_token",
				Name:        "Session Token (STS)",
				Description: "Temporary credentials with session token",
				Fields: []CredentialField{
					{Key: "access_key_id", Label: "Access Key ID", Type: FieldText, Required: true},
					{Key: "secret_access_key", Label: "Secret Access Key", Type: FieldPassword, Required: true},
					{Key: "session_token", Label: "Session Token", Type: FieldPassword, Required: true},
				},
				Injection: InjectionConfig{Type: InjectionNamedStrategy, Strategy: "aws_sigv4"},
			},
		},
	},
	{
		ID:          "facebook",
		DisplayName: "Facebook",
		Description: "Facebook Graph API",
		Icon:        "facebook",
		Target:      "https://graph.facebook.com",
		AuthMethods: []AuthMethod{
			{
				ID:          "facebook_oauth",
				Name:        "OAuth",
				Description: "Sign in with Facebook",
				Fields:      []CredentialField{},
				Injection:   InjectionConfig{Type: InjectionOAuth},
				AutoRefresh: true,
			},
		},
	},
	{
		ID:          "aws",
		DisplayName: "AWS",
		Description: "Amazon Web Services (S3, EC2, Lambda, etc.)",
		Icon:        "aws",
		Target:      "",
		AuthMethods: []AuthMethod{
			{
				ID:          "aws_access_key",
				Name:        "Access Key",
				Description: "IAM access key pair (most common)",
				KeyURL:      "https://console.aws.amazon.com/iam/home#/security_credentials",
				Fields: []CredentialField{
					{Key: "access_key_id", Label: "Access Key ID", Type: FieldText, Placeholder: "AKIAIOSFODNN7EXAMPLE", Required: true, Pattern: `^AKIA[A-Z0-9]{16}$`, HelpText: "20-character key starting with AKIA"},
					{Key: "secret_access_key", Label: "Secret Access Key", Type: FieldPassword, Placeholder: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", Required: true, HelpText: "40-character secret key"},
					{Key: "region", Label: "Default Region", Type: FieldText, Placeholder: "us-east-1", Required: false, HelpText: "e.g., us-east-1, eu-west-2"},
				},
				Injection: InjectionConfig{Type: InjectionNamedStrategy, Strategy: "connection_string"},
			},
			{
				ID:          "aws_session",
				Name:        "Session Credentials",
				Description: "Temporary credentials with session token (STS)",
				Fields: []CredentialField{
					{Key: "access_key_id", Label: "Access Key ID", Type: FieldText, Placeholder: "ASIAIOSFODNN7EXAMPLE", Required: true, HelpText: "Temporary key starting with ASIA"},
					{Key: "secret_access_key", Label: "Secret Access Key", Type: FieldPassword, Required: true},
					{Key: "session_token", Label: "Session Token", Type: FieldTextarea, Required: true, HelpText: "Temporary session token from STS"},
					{Key: "region", Label: "Default Region", Type: FieldText, Placeholder: "us-east-1", Required: false},
				},
				Injection: InjectionConfig{Type: InjectionNamedStrategy, Strategy: "connection_string"},
			},
			{
				ID:          "aws_profile",
				Name:        "Profile Name",
				Description: "Reference an existing AWS CLI profile",
				Fields: []CredentialField{
					{Key: "profile", Label: "Profile Name", Type: FieldText, Placeholder: "default", Required: true, HelpText: "Name of the profile in ~/.aws/credentials"},
					{Key: "region", Label: "Default Region", Type: FieldText, Placeholder: "us-east-1", Required: false},
				},
				Injection: InjectionConfig{Type: InjectionNamedStrategy, Strategy: "connection_string"},
			},
		},
	},
	{
		ID:          "gcp",
		DisplayName: "Google Cloud",
		Description: "Google Cloud Platform (Compute, Storage, BigQuery, etc.)",
		Icon:        "google",
		Target:      "",
		AuthMethods: []AuthMethod{
			{
				ID:          "gcp_service_account",
				Name:        "Service Account Key",
				Description: "JSON key file for a GCP service account",
				KeyURL:      "https://console.cloud.google.com/iam-admin/serviceaccounts",
				Fields: []CredentialField{
					{Key: "service_account_json", Label: "Service Account JSON", Type: FieldTextarea, Placeholder: "{\n  \"type\": \"service_account\",\n  \"project_id\": \"...\",\n  ...\n}", Required: true, Pattern: `^\s*\{`, HelpText: "Paste the entire JSON key file contents"},
					{Key: "project_id", Label: "Project ID (optional)", Type: FieldText, Placeholder: "my-project-123", Required: false, HelpText: "Overrides the project_id in the JSON if set"},
				},
				Injection: InjectionConfig{Type: InjectionNamedStrategy, Strategy: "connection_string"},
			},
			{
				ID:          "gcp_api_key",
				Name:        "API Key",
				Description: "Simple API key for GCP services that support it",
				KeyURL:      "https://console.cloud.google.com/apis/credentials",
				Fields: []CredentialField{
					{Key: "api_key", Label: "API Key", Type: FieldPassword, Required: true, HelpText: "API key from Google Cloud Console"},
				},
				Injection: InjectionConfig{Type: InjectionNamedStrategy, Strategy: "connection_string"},
			},
		},
	},
	{
		ID:          "azure",
		DisplayName: "Azure",
		Description: "Microsoft Azure (VMs, Storage, Functions, etc.)",
		Icon:        "microsoft",
		Target:      "",
		AuthMethods: []AuthMethod{
			{
				ID:          "azure_service_principal",
				Name:        "Service Principal",
				Description: "App registration with client ID and secret",
				KeyURL:      "https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps/ApplicationsListBlade",
				Fields: []CredentialField{
					{Key: "tenant_id", Label: "Tenant ID", Type: FieldText, Required: true, HelpText: "Azure AD tenant (directory) ID"},
					{Key: "client_id", Label: "Client ID", Type: FieldText, Required: true, HelpText: "Application (client) ID"},
					{Key: "client_secret", Label: "Client Secret", Type: FieldPassword, Required: true, HelpText: "Client secret value (not the secret ID)"},
					{Key: "subscription_id", Label: "Subscription ID (optional)", Type: FieldText, Required: false, HelpText: "Default Azure subscription"},
				},
				Injection: InjectionConfig{Type: InjectionNamedStrategy, Strategy: "connection_string"},
			},
			{
				ID:          "azure_connection_string",
				Name:        "Connection String",
				Description: "Azure service connection string (Storage, Service Bus, etc.)",
				Fields: []CredentialField{
					{Key: "connection_string", Label: "Connection String", Type: FieldPassword, Placeholder: "DefaultEndpointsProtocol=https;AccountName=...;AccountKey=...;", Required: true, HelpText: "Full Azure connection string"},
				},
				Injection: InjectionConfig{Type: InjectionNamedStrategy, Strategy: "connection_string"},
			},
		},
	},
	{
		ID:          "ssh",
		DisplayName: "SSH Key",
		Description: "Store SSH private keys for secure access",
		Icon:        "ssh",
		Target:      "",
		AuthMethods: []AuthMethod{
			{
				ID:          "ssh_private_key",
				Name:        "SSH Private Key",
				Description: "SSH private key (PEM or OpenSSH format)",
				Fields: []CredentialField{
					{
						Key:         "private_key",
						Label:       "Private Key",
						Type:        FieldTextarea,
						Placeholder: "-----BEGIN OPENSSH PRIVATE KEY-----\n...\n-----END OPENSSH PRIVATE KEY-----",
						Required:    true,
						Pattern:     `^-----BEGIN`,
						HelpText:    "Paste your SSH private key in PEM or OpenSSH format",
					},
					{
						Key:         "passphrase",
						Label:       "Passphrase (optional)",
						Type:        FieldPassword,
						Placeholder: "Leave empty if key has no passphrase",
						Required:    false,
					},
				},
				Injection: InjectionConfig{Type: InjectionNamedStrategy, Strategy: "ssh_key"},
			},
		},
	},
	{
		ID:          "postgresql",
		DisplayName: "PostgreSQL",
		Description: "PostgreSQL database connection",
		Icon:        "database",
		Target:      "",
		AuthMethods: []AuthMethod{
			{
				ID:          "postgres_uri",
				Name:        "Connection URI",
				Description: "Full PostgreSQL connection string",
				KeyURL:      "",
				Fields: []CredentialField{
					{
						Key:         "connection_uri",
						Label:       "Connection URI",
						Type:        FieldPassword,
						Placeholder: "postgresql://user:password@host:5432/dbname?sslmode=require",
						Required:    true,
						Pattern:     `^postgres(ql)?://`,
						HelpText:    "Format: postgresql://user:password@host:port/database",
					},
				},
				Injection: InjectionConfig{Type: InjectionNamedStrategy, Strategy: "connection_string"},
			},
			{
				ID:          "postgres_fields",
				Name:        "Host / User / Password",
				Description: "Individual connection parameters",
				Fields: []CredentialField{
					{Key: "host", Label: "Host", Type: FieldText, Placeholder: "localhost", Required: true},
					{Key: "port", Label: "Port", Type: FieldText, Placeholder: "5432", Required: false},
					{Key: "database", Label: "Database", Type: FieldText, Placeholder: "mydb", Required: true},
					{Key: "username", Label: "Username", Type: FieldText, Required: true},
					{Key: "password", Label: "Password", Type: FieldPassword, Required: true},
				},
				Injection: InjectionConfig{Type: InjectionNamedStrategy, Strategy: "connection_string"},
			},
		},
	},
	{
		ID:          "mysql",
		DisplayName: "MySQL",
		Description: "MySQL / MariaDB database connection",
		Icon:        "database",
		Target:      "",
		AuthMethods: []AuthMethod{
			{
				ID:          "mysql_uri",
				Name:        "Connection URI",
				Description: "Full MySQL connection string",
				Fields: []CredentialField{
					{
						Key:         "connection_uri",
						Label:       "Connection URI",
						Type:        FieldPassword,
						Placeholder: "mysql://user:password@host:3306/dbname",
						Required:    true,
						Pattern:     `^mysql://`,
						HelpText:    "Format: mysql://user:password@host:port/database",
					},
				},
				Injection: InjectionConfig{Type: InjectionNamedStrategy, Strategy: "connection_string"},
			},
			{
				ID:          "mysql_fields",
				Name:        "Host / User / Password",
				Description: "Individual connection parameters",
				Fields: []CredentialField{
					{Key: "host", Label: "Host", Type: FieldText, Placeholder: "localhost", Required: true},
					{Key: "port", Label: "Port", Type: FieldText, Placeholder: "3306", Required: false},
					{Key: "database", Label: "Database", Type: FieldText, Placeholder: "mydb", Required: true},
					{Key: "username", Label: "Username", Type: FieldText, Required: true},
					{Key: "password", Label: "Password", Type: FieldPassword, Required: true},
				},
				Injection: InjectionConfig{Type: InjectionNamedStrategy, Strategy: "connection_string"},
			},
		},
	},
	{
		ID:          "mongodb",
		DisplayName: "MongoDB",
		Description: "MongoDB database connection",
		Icon:        "database",
		Target:      "",
		AuthMethods: []AuthMethod{
			{
				ID:          "mongodb_uri",
				Name:        "Connection URI",
				Description: "Full MongoDB connection string",
				Fields: []CredentialField{
					{
						Key:         "connection_uri",
						Label:       "Connection URI",
						Type:        FieldPassword,
						Placeholder: "mongodb+srv://user:password@cluster.example.com/dbname",
						Required:    true,
						Pattern:     `^mongodb(\+srv)?://`,
						HelpText:    "Format: mongodb://user:password@host:port/database or mongodb+srv://...",
					},
				},
				Injection: InjectionConfig{Type: InjectionNamedStrategy, Strategy: "connection_string"},
			},
		},
	},
	{
		ID:          "redis",
		DisplayName: "Redis",
		Description: "Redis cache/database connection",
		Icon:        "database",
		Target:      "",
		AuthMethods: []AuthMethod{
			{
				ID:          "redis_uri",
				Name:        "Connection URI",
				Description: "Full Redis connection string",
				Fields: []CredentialField{
					{
						Key:         "connection_uri",
						Label:       "Connection URI",
						Type:        FieldPassword,
						Placeholder: "redis://user:password@host:6379/0",
						Required:    true,
						Pattern:     `^rediss?://`,
						HelpText:    "Format: redis://password@host:port/db or rediss:// for TLS",
					},
				},
				Injection: InjectionConfig{Type: InjectionNamedStrategy, Strategy: "connection_string"},
			},
		},
	},
	{
		ID:          "custom",
		DisplayName: "Custom Service",
		Description: "Configure a custom API service",
		Icon:        "custom",
		Target:      "",
		AuthMethods: []AuthMethod{
			{
				ID:          "api_key_bearer",
				Name:        "API Key (Bearer)",
				Description: "Token sent as Authorization Bearer header",
				Fields: []CredentialField{
					{Key: "token", Label: "API Key", Type: FieldPassword, Required: true},
				},
				Injection: InjectionConfig{Type: InjectionBearerHeader},
			},
			{
				ID:          "basic_auth",
				Name:        "Basic Auth",
				Description: "Username and password with HTTP Basic authentication",
				Fields: []CredentialField{
					{Key: "username", Label: "Username", Type: FieldText, Required: true},
					{Key: "password", Label: "Password", Type: FieldPassword, Required: true},
				},
				Injection: InjectionConfig{Type: InjectionBasicAuth},
			},
			{
				ID:          "query_param",
				Name:        "Query Parameter",
				Description: "Token sent as a URL query parameter",
				Fields: []CredentialField{
					{Key: "token", Label: "API Key", Type: FieldPassword, Required: true},
				},
				Injection: InjectionConfig{Type: InjectionQueryParam, QueryParam: "api_key"},
			},
			{
				ID:          "custom_oauth",
				Name:        "OAuth",
				Description: "Browser-based OAuth authorization",
				Fields:      []CredentialField{},
				Injection:   InjectionConfig{Type: InjectionOAuth},
			},
		},
	},
}
