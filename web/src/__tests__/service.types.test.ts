/**
 * Type-level tests for service types.
 * These compile-time checks ensure the types are correctly shaped.
 * Runtime tests validate the API contract shapes.
 */
import { describe, it, expect } from 'vitest';
import type {
  Service,
  ServiceTemplate,
  CreateServiceRequest,
  UpdateServiceRequest,
  CredentialStatus,
  AuthMethod,
  CredentialField,
  InjectionConfig,
} from '../types/service';

const MOCK_AUTH_METHOD: AuthMethod = {
  id: 'github_pat',
  name: 'Personal Access Token',
  description: 'GitHub PAT',
  fields: [
    {
      key: 'token',
      label: 'Token',
      type: 'password',
      required: true,
    },
  ],
  injection: { type: 'bearer_header' },
};

describe('Service type shape', () => {
  it('has required fields with correct union types', () => {
    const service: Service = {
      name: 'stripe',
      type: 'http_proxy',
      target: 'https://api.stripe.com',
      inject: 'header',
      status: 'available',
      created_at: '2026-03-22T00:00:00Z',
      updated_at: '2026-03-22T00:00:00Z',
    };
    expect(service.name).toBe('stripe');
    expect(service.type).toBe('http_proxy');
    expect(service.status).toBe('available');
  });

  it('accepts oauth type', () => {
    const service: Service = {
      name: 'github',
      type: 'oauth',
      target: 'https://api.github.com',
      inject: 'header',
      status: 'not_configured',
      created_at: '2026-03-22T00:00:00Z',
      updated_at: '2026-03-22T00:00:00Z',
    };
    expect(service.type).toBe('oauth');
    expect(service.status).toBe('not_configured');
  });

  it('accepts optional header_template field', () => {
    const service: Service = {
      name: 'openai',
      type: 'http_proxy',
      target: 'https://api.openai.com',
      inject: 'header',
      header_template: 'Bearer {{.secret}}',
      status: 'available',
      created_at: '2026-03-22T00:00:00Z',
      updated_at: '2026-03-22T00:00:00Z',
    };
    expect(service.header_template).toBe('Bearer {{.secret}}');
  });

  it('accepts query inject with query_param', () => {
    const service: Service = {
      name: 'weather',
      type: 'http_proxy',
      target: 'https://api.weather.com',
      inject: 'query',
      query_param: 'api_key',
      status: 'expired',
      created_at: '2026-03-22T00:00:00Z',
      updated_at: '2026-03-22T00:00:00Z',
    };
    expect(service.inject).toBe('query');
    expect(service.query_param).toBe('api_key');
  });

  it('accepts auth_method and auth_method_name fields', () => {
    const service: Service = {
      name: 'github',
      type: 'http_proxy',
      target: 'https://api.github.com',
      inject: 'header',
      status: 'available',
      auth_method: 'github_pat_classic',
      auth_method_name: 'Personal Access Token (classic)',
      created_at: '2026-03-22T00:00:00Z',
      updated_at: '2026-03-22T00:00:00Z',
    };
    expect(service.auth_method).toBe('github_pat_classic');
    expect(service.auth_method_name).toBe('Personal Access Token (classic)');
  });
});

describe('ServiceTemplate type shape', () => {
  it('has required fields including auth_methods', () => {
    const template: ServiceTemplate = {
      id: 'stripe',
      display_name: 'Stripe',
      target: 'https://api.stripe.com',
      description: 'Stripe payment API',
      auth_methods: [MOCK_AUTH_METHOD],
    };
    expect(template.id).toBe('stripe');
    expect(template.display_name).toBe('Stripe');
    expect(template.auth_methods).toHaveLength(1);
  });

  it('accepts optional icon field', () => {
    const template: ServiceTemplate = {
      id: 'github',
      display_name: 'GitHub',
      target: 'https://api.github.com',
      icon: 'github',
      auth_methods: [MOCK_AUTH_METHOD],
    };
    expect(template.icon).toBe('github');
  });
});

describe('AuthMethod type shape', () => {
  it('has required fields', () => {
    const method: AuthMethod = {
      id: 'github_pat',
      name: 'Personal Access Token',
      description: 'Use a PAT',
      fields: [],
      injection: { type: 'bearer_header' },
    };
    expect(method.id).toBe('github_pat');
    expect(method.fields).toEqual([]);
  });

  it('accepts auto_refresh and token_prefix', () => {
    const method: AuthMethod = {
      id: 'github_pat',
      name: 'PAT',
      description: 'Token',
      fields: [],
      injection: { type: 'bearer_header' },
      auto_refresh: false,
      token_prefix: 'ghp_',
    };
    expect(method.auto_refresh).toBe(false);
    expect(method.token_prefix).toBe('ghp_');
  });
});

describe('CredentialField type shape', () => {
  it('accepts all field types', () => {
    const textField: CredentialField = { key: 'user', label: 'Username', type: 'text', required: true };
    const pwField: CredentialField = { key: 'pass', label: 'Password', type: 'password', required: true };
    const taField: CredentialField = { key: 'key', label: 'PEM Key', type: 'textarea', required: false };
    expect(textField.type).toBe('text');
    expect(pwField.type).toBe('password');
    expect(taField.type).toBe('textarea');
  });

  it('accepts optional pattern and help_text', () => {
    const field: CredentialField = {
      key: 'token',
      label: 'Token',
      type: 'password',
      required: true,
      pattern: '^ghp_',
      help_text: 'Create at github.com/settings/tokens',
    };
    expect(field.pattern).toBe('^ghp_');
    expect(field.help_text).toContain('github.com');
  });
});

describe('InjectionConfig type shape', () => {
  it('accepts bearer_header type', () => {
    const config: InjectionConfig = { type: 'bearer_header' };
    expect(config.type).toBe('bearer_header');
  });

  it('accepts custom_header with header_name and template', () => {
    const config: InjectionConfig = {
      type: 'custom_header',
      header_name: 'X-API-Key',
      header_template: '{{.Secret}}',
    };
    expect(config.header_name).toBe('X-API-Key');
  });

  it('accepts oauth type', () => {
    const config: InjectionConfig = { type: 'oauth' };
    expect(config.type).toBe('oauth');
  });
});

describe('CreateServiceRequest type shape', () => {
  it('has required fields', () => {
    const req: CreateServiceRequest = {
      name: 'stripe',
      type: 'http_proxy',
      target: 'https://api.stripe.com',
    };
    expect(req.name).toBe('stripe');
  });

  it('accepts new auth_method and credentials fields', () => {
    const req: CreateServiceRequest = {
      name: 'github',
      type: 'http_proxy',
      target: 'https://api.github.com',
      auth_method: 'github_pat_classic',
      credentials: { token: 'ghp_xxx' },
    };
    expect(req.auth_method).toBe('github_pat_classic');
    expect(req.credentials).toEqual({ token: 'ghp_xxx' });
  });

  it('accepts legacy fields for backward compat', () => {
    const req: CreateServiceRequest = {
      name: 'stripe',
      type: 'http_proxy',
      target: 'https://api.stripe.com',
      inject: 'header',
      credential: 'sk_live_test',
      header_template: 'Bearer {{.secret}}',
    };
    expect(req.credential).toBe('sk_live_test');
    expect(req.inject).toBe('header');
  });
});

describe('UpdateServiceRequest type shape', () => {
  it('allows all fields to be optional', () => {
    const req: UpdateServiceRequest = {};
    expect(req).toEqual({});
  });

  it('accepts legacy credential field', () => {
    const req: UpdateServiceRequest = { credential: 'new_secret' };
    expect(req.credential).toBe('new_secret');
  });

  it('accepts new credentials map', () => {
    const req: UpdateServiceRequest = {
      credentials: { token: 'new_token', username: 'admin' },
    };
    expect(req.credentials).toEqual({ token: 'new_token', username: 'admin' });
  });
});

describe('CredentialStatus type shape', () => {
  it('has required fields', () => {
    const status: CredentialStatus = {
      status: 'available',
      service: 'stripe',
    };
    expect(status.status).toBe('available');
    expect(status.service).toBe('stripe');
  });

  it('accepts optional auth_method field', () => {
    const status: CredentialStatus = {
      status: 'expired',
      service: 'github',
      auth_method: 'github_pat_classic',
    };
    expect(status.auth_method).toBe('github_pat_classic');
  });
});
