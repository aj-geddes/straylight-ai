package services

// DatabaseTemplate holds metadata for a database service template.
// It describes the engine type, default port, and creation/revocation SQL.
type DatabaseTemplate struct {
	// Engine is the database engine: postgresql, mysql, or redis.
	Engine string
	// DefaultPort is the well-known port for this engine.
	DefaultPort int
	// Description is a human-friendly description of the engine.
	Description string
	// CreationStatements are OpenBao SQL statements used to create a temp user.
	// Uses OpenBao placeholders: {{name}}, {{password}}, {{expiration}}.
	CreationStatements []string
	// RevocationStatements are SQL statements used to remove the temp user.
	RevocationStatements []string
}

// DatabaseTemplates is the built-in catalog of database engine templates.
// Each entry describes how to configure OpenBao for that engine.
var DatabaseTemplates = map[string]DatabaseTemplate{
	"postgresql": {
		Engine:      "postgresql",
		DefaultPort: 5432,
		Description: "PostgreSQL relational database",
		CreationStatements: []string{
			`CREATE ROLE "{{name}}" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';`,
			`GRANT SELECT ON ALL TABLES IN SCHEMA public TO "{{name}}";`,
		},
		RevocationStatements: []string{
			`REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM "{{name}}";`,
			`DROP ROLE IF EXISTS "{{name}}";`,
		},
	},
	"mysql": {
		Engine:      "mysql",
		DefaultPort: 3306,
		Description: "MySQL / MariaDB relational database",
		CreationStatements: []string{
			`CREATE USER '{{name}}'@'%' IDENTIFIED BY '{{password}}';`,
			`GRANT SELECT ON *.* TO '{{name}}'@'%';`,
		},
		RevocationStatements: []string{
			`REVOKE ALL PRIVILEGES, GRANT OPTION FROM '{{name}}'@'%';`,
			`DROP USER IF EXISTS '{{name}}'@'%';`,
		},
	},
	"redis": {
		Engine:      "redis",
		DefaultPort: 6379,
		Description: "Redis in-memory data store",
		// Redis uses ACL commands instead of SQL.
		CreationStatements: []string{
			`ACL SETUSER "{{name}}" on >"{{password}}" ~* +@read`,
		},
		RevocationStatements: []string{
			`ACL DELUSER "{{name}}"`,
		},
	},
}

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
