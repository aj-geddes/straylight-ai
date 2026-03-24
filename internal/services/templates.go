package services

// Templates is the legacy map of pre-configured service templates.
// It is preserved for backward compatibility with existing code that references
// Templates["stripe"], Templates["google"], etc.
//
// New code should use ServiceTemplates which contains ServiceTemplate objects
// with multi-auth-method support.
//
// Deprecated: Use ServiceTemplates instead.
var Templates = map[string]Service{
	"stripe": {
		Name:           "stripe",
		Type:           "http_proxy",
		Target:         "https://api.stripe.com",
		Inject:         "header",
		HeaderTemplate: "Bearer {{.secret}}",
		DefaultHeaders: map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
		},
	},
	"github": {
		Name:           "github",
		Type:           "http_proxy",
		Target:         "https://api.github.com",
		Inject:         "header",
		HeaderTemplate: "Bearer {{.secret}}",
		DefaultHeaders: map[string]string{
			"Accept":               "application/vnd.github+json",
			"X-GitHub-Api-Version": "2022-11-28",
		},
	},
	"openai": {
		Name:           "openai",
		Type:           "http_proxy",
		Target:         "https://api.openai.com",
		Inject:         "header",
		HeaderTemplate: "Bearer {{.secret}}",
		DefaultHeaders: map[string]string{
			"Content-Type": "application/json",
		},
	},
	"anthropic": {
		Name:           "anthropic",
		Type:           "http_proxy",
		Target:         "https://api.anthropic.com",
		Inject:         "header",
		HeaderTemplate: "{{.secret}}",
		DefaultHeaders: map[string]string{
			"Content-Type": "application/json",
		},
	},
	"gitlab": {
		Name:           "gitlab",
		Type:           "http_proxy",
		Target:         "https://gitlab.com/api/v4",
		Inject:         "header",
		HeaderTemplate: "Bearer {{.secret}}",
	},
	"slack": {
		Name:           "slack",
		Type:           "http_proxy",
		Target:         "https://slack.com/api",
		Inject:         "header",
		HeaderTemplate: "Bearer {{.secret}}",
	},
	"google": {
		Name:           "google",
		Type:           "oauth",
		Target:         "https://www.googleapis.com",
		Inject:         "header",
		HeaderTemplate: "Bearer {{.secret}}",
	},
	"stripe-connect": {
		Name:           "stripe-connect",
		Type:           "oauth",
		Target:         "https://api.stripe.com",
		Inject:         "header",
		HeaderTemplate: "Bearer {{.secret}}",
	},
}
