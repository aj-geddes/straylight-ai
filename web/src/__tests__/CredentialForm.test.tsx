import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { CredentialForm } from '../components/CredentialForm';
import type { CredentialField } from '../types/service';

const TEXT_FIELD: CredentialField = {
  key: 'username',
  label: 'Username',
  type: 'text',
  placeholder: 'Enter username',
  required: true,
};

const PASSWORD_FIELD: CredentialField = {
  key: 'token',
  label: 'API Token',
  type: 'password',
  placeholder: 'ghp_xxxxxxxxxxxx',
  required: true,
  pattern: '^ghp_',
  help_text: 'Create a token at github.com/settings/tokens',
};

const TEXTAREA_FIELD: CredentialField = {
  key: 'private_key',
  label: 'Private Key',
  type: 'textarea',
  placeholder: '-----BEGIN PRIVATE KEY-----',
  required: true,
};

describe('CredentialForm - rendering', () => {
  it('renders a text input for text fields', () => {
    render(<CredentialForm fields={[TEXT_FIELD]} values={{}} onChange={vi.fn()} errors={{}} />);
    expect(screen.getByLabelText(/username/i)).toHaveAttribute('type', 'text');
  });

  it('renders a password input for password fields', () => {
    render(<CredentialForm fields={[PASSWORD_FIELD]} values={{}} onChange={vi.fn()} errors={{}} />);
    expect(screen.getByLabelText(/api token/i)).toHaveAttribute('type', 'password');
  });

  it('renders a textarea for textarea fields', () => {
    render(<CredentialForm fields={[TEXTAREA_FIELD]} values={{}} onChange={vi.fn()} errors={{}} />);
    expect(screen.getByLabelText(/private key/i).tagName).toBe('TEXTAREA');
  });

  it('renders placeholder text', () => {
    render(<CredentialForm fields={[TEXT_FIELD]} values={{}} onChange={vi.fn()} errors={{}} />);
    expect(screen.getByPlaceholderText('Enter username')).toBeInTheDocument();
  });

  it('renders help text when provided', () => {
    render(<CredentialForm fields={[PASSWORD_FIELD]} values={{}} onChange={vi.fn()} errors={{}} />);
    expect(screen.getByText(/create a token at github.com/i)).toBeInTheDocument();
  });

  it('renders multiple fields', () => {
    render(
      <CredentialForm
        fields={[TEXT_FIELD, PASSWORD_FIELD]}
        values={{}}
        onChange={vi.fn()}
        errors={{}}
      />
    );
    expect(screen.getByLabelText(/username/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/api token/i)).toBeInTheDocument();
  });

  it('shows a show/hide toggle for password fields', () => {
    render(<CredentialForm fields={[PASSWORD_FIELD]} values={{}} onChange={vi.fn()} errors={{}} />);
    expect(screen.getByRole('button', { name: /show|hide/i })).toBeInTheDocument();
  });

  it('shows field-level validation error', () => {
    render(
      <CredentialForm
        fields={[PASSWORD_FIELD]}
        values={{}}
        onChange={vi.fn()}
        errors={{ token: 'Token is required' }}
      />
    );
    expect(screen.getByText('Token is required')).toBeInTheDocument();
  });
});

describe('CredentialForm - password show/hide', () => {
  it('reveals password when show button is clicked', async () => {
    const user = userEvent.setup();
    render(<CredentialForm fields={[PASSWORD_FIELD]} values={{ token: 'secret' }} onChange={vi.fn()} errors={{}} />);
    const input = screen.getByLabelText(/api token/i);
    expect(input).toHaveAttribute('type', 'password');
    await user.click(screen.getByRole('button', { name: /show/i }));
    expect(input).toHaveAttribute('type', 'text');
  });

  it('masks password again when hide button is clicked', async () => {
    const user = userEvent.setup();
    render(<CredentialForm fields={[PASSWORD_FIELD]} values={{ token: 'secret' }} onChange={vi.fn()} errors={{}} />);
    await user.click(screen.getByRole('button', { name: /show/i }));
    await user.click(screen.getByRole('button', { name: /hide/i }));
    expect(screen.getByLabelText(/api token/i)).toHaveAttribute('type', 'password');
  });
});

describe('CredentialForm - interaction', () => {
  it('calls onChange with field key and value when input changes', () => {
    const onChange = vi.fn();
    render(<CredentialForm fields={[TEXT_FIELD]} values={{}} onChange={onChange} errors={{}} />);
    fireEvent.change(screen.getByLabelText(/username/i), { target: { value: 'alice' } });
    expect(onChange).toHaveBeenCalledWith('username', 'alice');
  });

  it('displays current value from values prop', () => {
    render(
      <CredentialForm
        fields={[TEXT_FIELD]}
        values={{ username: 'alice' }}
        onChange={vi.fn()}
        errors={{}}
      />
    );
    expect(screen.getByLabelText(/username/i)).toHaveValue('alice');
  });
});
