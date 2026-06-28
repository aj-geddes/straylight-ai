package services

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// LoadCommunityTemplates reads every *.yaml, *.yml, and *.json file in dir,
// attempts to parse each as a ServiceTemplate, validates it via ValidateTemplate,
// and returns the valid templates. Invalid files are recorded in errs and skipped
// — one bad file never aborts loading of the rest, and never panics (unlike the
// compiled init() which uses regexp.MustCompile). The dir is not recursed.
func LoadCommunityTemplates(dir string) (loaded []ServiceTemplate, errs []error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		// Non-existent or unreadable directory: return empty with no error.
		return nil, nil
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		ext := strings.ToLower(filepath.Ext(name))
		if ext != ".yaml" && ext != ".yml" && ext != ".json" {
			continue
		}

		path := filepath.Join(dir, name)
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			errs = append(errs, fmt.Errorf("loader: %s: %w", name, readErr))
			continue
		}

		var tmpl ServiceTemplate
		if ext == ".json" {
			if parseErr := json.Unmarshal(data, &tmpl); parseErr != nil {
				errs = append(errs, fmt.Errorf("loader: %s: %w", name, parseErr))
				continue
			}
		} else {
			if parseErr := yaml.Unmarshal(data, &tmpl); parseErr != nil {
				errs = append(errs, fmt.Errorf("loader: %s: %w", name, parseErr))
				continue
			}
		}

		// Validate patterns defensively (no MustCompile; return error instead of panic).
		if patErr := validateTemplatePatterns(tmpl); patErr != nil {
			errs = append(errs, fmt.Errorf("loader: %s: %w", name, patErr))
			continue
		}

		// Structural validation via the same path as built-ins.
		if valErr := ValidateTemplate(tmpl); valErr != nil {
			errs = append(errs, fmt.Errorf("loader: %s: %w", name, valErr))
			continue
		}

		loaded = append(loaded, tmpl)
	}
	return loaded, errs
}

// validateTemplatePatterns compiles each CredentialField.Pattern in tmpl without
// calling regexp.MustCompile — it returns an error for any invalid pattern, so
// a bad community file is skipped rather than panicking at startup.
func validateTemplatePatterns(tmpl ServiceTemplate) error {
	for _, am := range tmpl.AuthMethods {
		for _, field := range am.Fields {
			if field.Pattern == "" {
				continue
			}
			if _, err := regexp.Compile(field.Pattern); err != nil {
				return fmt.Errorf("auth method %q field %q has invalid pattern: %w", am.ID, field.Key, err)
			}
		}
	}
	return nil
}

// MergeTemplates overlays community templates onto built-ins by ID. Built-ins
// always win on ID collision (a community file cannot silently shadow a shipped
// template); collisions are recorded as warning strings.
func MergeTemplates(builtin, community []ServiceTemplate) (merged []ServiceTemplate, warnings []string) {
	// Index built-ins by ID.
	seen := make(map[string]bool, len(builtin))
	merged = make([]ServiceTemplate, 0, len(builtin)+len(community))
	merged = append(merged, builtin...)
	for _, t := range builtin {
		seen[t.ID] = true
	}

	for _, ct := range community {
		if seen[ct.ID] {
			warnings = append(warnings, fmt.Sprintf("community template %q skipped: id collides with a built-in", ct.ID))
			continue
		}
		seen[ct.ID] = true
		merged = append(merged, ct)
	}
	return merged, warnings
}
