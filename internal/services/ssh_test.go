package services_test

import (
	"testing"

	"github.com/straylight-ai/straylight/internal/services"
)

// TestSSHTemplate_IsPresentInServiceTemplates verifies the SSH template is in the catalog.
func TestSSHTemplate_IsPresentInServiceTemplates(t *testing.T) {
	var found bool
	for _, tmpl := range services.ServiceTemplates {
		if tmpl.ID == "ssh" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected 'ssh' template in ServiceTemplates")
	}
}

// TestSSHTemplate_HasSSHPrivateKeyAuthMethod verifies the SSH template has the
// ssh_private_key auth method.
func TestSSHTemplate_HasSSHPrivateKeyAuthMethod(t *testing.T) {
	var sshTmpl *services.ServiceTemplate
	for i := range services.ServiceTemplates {
		if services.ServiceTemplates[i].ID == "ssh" {
			tmpl := services.ServiceTemplates[i]
			sshTmpl = &tmpl
			break
		}
	}
	if sshTmpl == nil {
		t.Fatal("expected 'ssh' template")
	}

	var found bool
	for _, am := range sshTmpl.AuthMethods {
		if am.ID == "ssh_private_key" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected 'ssh_private_key' auth method in SSH template")
	}
}

// TestSSHTemplate_PassesValidation verifies the SSH template passes ValidateTemplate.
func TestSSHTemplate_PassesValidation(t *testing.T) {
	var sshTmpl *services.ServiceTemplate
	for i := range services.ServiceTemplates {
		if services.ServiceTemplates[i].ID == "ssh" {
			tmpl := services.ServiceTemplates[i]
			sshTmpl = &tmpl
			break
		}
	}
	if sshTmpl == nil {
		t.Fatal("expected 'ssh' template")
	}
	if err := services.ValidateTemplate(*sshTmpl); err != nil {
		t.Errorf("SSH template failed validation: %v", err)
	}
}

// TestSSHTemplate_PrivateKeyFieldIsRequired verifies the private_key field is required.
func TestSSHTemplate_PrivateKeyFieldIsRequired(t *testing.T) {
	var sshMethod *services.AuthMethod
	for i := range services.ServiceTemplates {
		if services.ServiceTemplates[i].ID == "ssh" {
			for j := range services.ServiceTemplates[i].AuthMethods {
				if services.ServiceTemplates[i].AuthMethods[j].ID == "ssh_private_key" {
					m := services.ServiceTemplates[i].AuthMethods[j]
					sshMethod = &m
					break
				}
			}
		}
	}
	if sshMethod == nil {
		t.Fatal("expected 'ssh_private_key' auth method")
	}

	var privateKeyField *services.CredentialField
	for _, f := range sshMethod.Fields {
		if f.Key == "private_key" {
			pf := f
			privateKeyField = &pf
			break
		}
	}
	if privateKeyField == nil {
		t.Fatal("expected 'private_key' field in ssh_private_key auth method")
	}
	if !privateKeyField.Required {
		t.Error("expected private_key field to be required")
	}
}

// TestSSHTemplate_PassphraseFieldIsOptional verifies passphrase is not required.
func TestSSHTemplate_PassphraseFieldIsOptional(t *testing.T) {
	var sshMethod *services.AuthMethod
	for i := range services.ServiceTemplates {
		if services.ServiceTemplates[i].ID == "ssh" {
			for j := range services.ServiceTemplates[i].AuthMethods {
				if services.ServiceTemplates[i].AuthMethods[j].ID == "ssh_private_key" {
					m := services.ServiceTemplates[i].AuthMethods[j]
					sshMethod = &m
					break
				}
			}
		}
	}
	if sshMethod == nil {
		t.Fatal("expected 'ssh_private_key' auth method")
	}

	for _, f := range sshMethod.Fields {
		if f.Key == "passphrase" {
			if f.Required {
				t.Error("expected passphrase field to be optional (not required)")
			}
			return
		}
	}
	t.Error("expected 'passphrase' field in ssh_private_key auth method")
}

// TestFilterTemplatesForPersonalTier_IncludesSSH verifies that the SSH template
// is included in personal tier after the filter allows ssh_key named_strategy.
func TestFilterTemplatesForPersonalTier_IncludesSSH(t *testing.T) {
	filtered := services.FilterTemplatesForPersonalTier(services.ServiceTemplates)

	var found bool
	for _, tmpl := range filtered {
		if tmpl.ID == "ssh" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected 'ssh' template to be present in personal tier filtered templates")
	}
}

// TestFilterTemplatesForPersonalTier_SSHHasSSHKeyMethod verifies that the
// ssh_private_key method survives the personal tier filter.
func TestFilterTemplatesForPersonalTier_SSHHasSSHKeyMethod(t *testing.T) {
	filtered := services.FilterTemplatesForPersonalTier(services.ServiceTemplates)

	for _, tmpl := range filtered {
		if tmpl.ID == "ssh" {
			for _, am := range tmpl.AuthMethods {
				if am.ID == "ssh_private_key" {
					return
				}
			}
			t.Error("expected 'ssh_private_key' method in filtered SSH template")
			return
		}
	}
	t.Error("expected 'ssh' template in filtered templates")
}
