export type ServiceType = 'http_proxy' | 'oauth';

export type ServiceStatus = 'available' | 'expired' | 'not_configured';

export type InjectMethod = 'header' | 'query';

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
  /** URL where the user can obtain or manage this credential. */
  key_url?: string;
}

export interface AccountInfo {
  display_name?: string;
  username?: string;
  email?: string;
  avatar_url?: string;
  url?: string;
  plan?: string;
  extra?: Record<string, string>;
}

export interface Service {
  name: string;
  type: ServiceType;
  target: string;
  inject: InjectMethod;
  header_template?: string;
  query_param?: string;
  default_headers?: Record<string, string>;
  auth_method?: string;
  auth_method_name?: string;
  status: ServiceStatus;
  created_at: string;
  updated_at: string;
  account_info?: AccountInfo;
}

/**
 * ServiceTemplate now includes auth_methods array for multi-auth support.
 * Legacy fields (name, type, inject, header_template) kept for backward compat.
 */
export interface ServiceTemplate {
  id: string;
  display_name: string;
  description?: string;
  icon?: string;
  target: string;
  default_headers?: Record<string, string>;
  auth_methods: AuthMethod[];
  exec_config?: {
    env_var: string;
  };
  // Legacy fields kept for backward compat with existing tests
  name?: string;
  type?: ServiceType;
  inject?: string;
  header_template?: string;
}

/**
 * CreateServiceRequest supports both new multi-field and legacy single-field formats.
 */
export interface CreateServiceRequest {
  name: string;
  type?: string;
  target?: string;
  template?: string;
  auth_method?: string;
  credentials?: Record<string, string>;
  // Legacy fields kept for backward compat
  inject?: string;
  credential?: string;
  header_template?: string;
  header_name?: string;
  query_param?: string;
  default_headers?: Record<string, string>;
  exec_config?: {
    env_var: string;
  };
}

export interface UpdateServiceRequest {
  target?: string;
  auth_method?: string;
  credentials?: Record<string, string>;
  // Legacy fields kept for backward compat
  credential?: string;
  header_template?: string;
}

export interface CredentialStatus {
  status: ServiceStatus;
  service: string;
  auth_method?: string;
}

/** New-format request used by AddServiceDialog. */
export interface AddServiceRequest {
  template: string;
  auth_method: string;
  credentials: Record<string, string>;
  name?: string;
}
