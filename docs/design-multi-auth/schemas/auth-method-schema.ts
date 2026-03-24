// =============================================================================
// Proposed TypeScript type additions for multi-auth-method support.
// This file is a design artifact showing the exact types to add/modify in
// web/src/types/service.ts
// =============================================================================

// --- NEW TYPES ---

export type InjectionType =
  | 'bearer_header'
  | 'custom_header'
  | 'multi_header'
  | 'query_param'
  | 'basic_auth'
  | 'oauth'
  | 'named_strategy';

export type FieldType = 'password' | 'text' | 'textarea';

export interface CredentialField {
  key: string;
  label: string;
  type: FieldType;
  placeholder?: string;
  required: boolean;
  pattern?: string;
  help_text?: string;
}

export interface InjectionConfig {
  type: InjectionType;
  header_name?: string;
  header_template?: string;
  query_param?: string;
  headers?: Record<string, string>;
  strategy?: string;
}

export interface AuthMethod {
  id: string;
  name: string;
  description: string;
  fields: CredentialField[];
  injection: InjectionConfig;
  auto_refresh?: boolean;
  token_prefix?: string;
}

// --- UPDATED TYPES ---

/**
 * ServiceTemplate now includes auth_methods instead of flat credential_fields.
 * Replaces the existing ServiceTemplate interface.
 */
export interface ServiceTemplate {
  id: string;
  display_name: string;
  description: string;
  icon?: string;
  target: string;
  default_headers?: Record<string, string>;
  auth_methods: AuthMethod[];
  exec_config?: {
    env_var: string;
  };
}

/**
 * Service now includes auth_method (the chosen method ID).
 * Extends the existing Service interface.
 */
export interface Service {
  name: string;
  type: ServiceType;
  target: string;
  inject: InjectMethod;             // DEPRECATED: kept for backward compat
  header_template?: string;         // DEPRECATED
  query_param?: string;             // DEPRECATED
  default_headers?: Record<string, string>;
  auth_method?: string;             // NEW: ID of the chosen auth method
  auth_method_name?: string;        // NEW: Human-readable name (resolved)
  status: ServiceStatus;
  created_at: string;
  updated_at: string;
}

/**
 * CreateServiceRequest supports both new multi-field and legacy single-field.
 */
export interface CreateServiceRequest {
  name: string;
  type: string;
  target: string;
  auth_method?: string;             // NEW: ID of the chosen auth method
  credentials?: Record<string, string>; // NEW: Multi-field credentials
  credential?: string;              // DEPRECATED: Legacy single field
  inject?: string;                  // DEPRECATED
  header_template?: string;         // DEPRECATED
  header_name?: string;             // DEPRECATED
  query_param?: string;             // DEPRECATED
  default_headers?: Record<string, string>;
  exec_config?: {
    env_var: string;
  };
}

/**
 * UpdateServiceRequest supports both new multi-field and legacy.
 */
export interface UpdateServiceRequest {
  target?: string;
  auth_method?: string;             // NEW
  credentials?: Record<string, string>; // NEW
  credential?: string;              // DEPRECATED
  header_template?: string;         // DEPRECATED
}

// Existing types unchanged:
export type ServiceType = 'http_proxy' | 'oauth';
export type ServiceStatus = 'available' | 'expired' | 'not_configured';
export type InjectMethod = 'header' | 'query';

export interface CredentialStatus {
  status: ServiceStatus;
  service: string;
  auth_method?: string;             // NEW
}
