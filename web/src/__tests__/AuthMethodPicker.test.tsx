import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { AuthMethodPicker } from '../components/AuthMethodPicker';
import type { AuthMethod } from '../types/service';

const PAT_METHOD: AuthMethod = {
  id: 'github_pat_classic',
  name: 'Personal Access Token (classic)',
  description: 'Use a personal access token for authentication',
  fields: [
    {
      key: 'token',
      label: 'Personal Access Token',
      type: 'password',
      placeholder: 'ghp_xxxxxxxxxxxx',
      required: true,
    },
  ],
  injection: { type: 'bearer_header' },
};

const OAUTH_METHOD: AuthMethod = {
  id: 'github_oauth',
  name: 'OAuth',
  description: 'Connect via OAuth flow',
  fields: [],
  injection: { type: 'oauth' },
};

describe('AuthMethodPicker - rendering', () => {
  it('renders all provided auth methods', () => {
    render(
      <AuthMethodPicker
        methods={[PAT_METHOD, OAUTH_METHOD]}
        selectedId={null}
        onSelect={vi.fn()}
      />
    );
    expect(screen.getByText('Personal Access Token (classic)')).toBeInTheDocument();
    expect(screen.getByText('OAuth')).toBeInTheDocument();
  });

  it('renders descriptions for each method', () => {
    render(
      <AuthMethodPicker
        methods={[PAT_METHOD]}
        selectedId={null}
        onSelect={vi.fn()}
      />
    );
    expect(screen.getByText('Use a personal access token for authentication')).toBeInTheDocument();
  });

  it('marks the selected method as checked', () => {
    render(
      <AuthMethodPicker
        methods={[PAT_METHOD, OAUTH_METHOD]}
        selectedId="github_pat_classic"
        onSelect={vi.fn()}
      />
    );
    const patInput = screen.getByDisplayValue('github_pat_classic');
    expect(patInput).toBeChecked();
  });

  it('marks the unselected method as unchecked', () => {
    render(
      <AuthMethodPicker
        methods={[PAT_METHOD, OAUTH_METHOD]}
        selectedId="github_pat_classic"
        onSelect={vi.fn()}
      />
    );
    const oauthInput = screen.getByDisplayValue('github_oauth');
    expect(oauthInput).not.toBeChecked();
  });

  it('renders radio inputs for each method', () => {
    render(
      <AuthMethodPicker
        methods={[PAT_METHOD, OAUTH_METHOD]}
        selectedId={null}
        onSelect={vi.fn()}
      />
    );
    const radios = screen.getAllByRole('radio');
    expect(radios).toHaveLength(2);
  });
});

describe('AuthMethodPicker - interaction', () => {
  it('calls onSelect with method id when radio is clicked', () => {
    const onSelect = vi.fn();
    render(
      <AuthMethodPicker
        methods={[PAT_METHOD, OAUTH_METHOD]}
        selectedId={null}
        onSelect={onSelect}
      />
    );
    fireEvent.click(screen.getByDisplayValue('github_pat_classic'));
    expect(onSelect).toHaveBeenCalledWith('github_pat_classic');
  });

  it('calls onSelect with correct id for each method', () => {
    const onSelect = vi.fn();
    render(
      <AuthMethodPicker
        methods={[PAT_METHOD, OAUTH_METHOD]}
        selectedId={null}
        onSelect={onSelect}
      />
    );
    fireEvent.click(screen.getByDisplayValue('github_oauth'));
    expect(onSelect).toHaveBeenCalledWith('github_oauth');
  });
});
