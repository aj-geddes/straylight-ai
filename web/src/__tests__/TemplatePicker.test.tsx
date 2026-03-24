import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { TemplatePicker } from '../components/TemplatePicker';
import type { ServiceTemplate } from '../types/service';

const MOCK_TEMPLATES: ServiceTemplate[] = [
  {
    id: 'stripe',
    display_name: 'Stripe',
    target: 'https://api.stripe.com',
    description: 'Stripe payment API',
    auth_methods: [
      {
        id: 'stripe_api_key',
        name: 'API Key',
        description: 'Stripe secret key',
        fields: [{ key: 'token', label: 'API Key', type: 'password', required: true }],
        injection: { type: 'bearer_header' },
      },
    ],
  },
  {
    id: 'github',
    display_name: 'GitHub',
    target: 'https://api.github.com',
    description: 'GitHub API',
    auth_methods: [
      {
        id: 'github_pat',
        name: 'Personal Access Token',
        description: 'GitHub PAT',
        fields: [{ key: 'token', label: 'Token', type: 'password', required: true }],
        injection: { type: 'bearer_header' },
      },
    ],
  },
  {
    id: 'openai',
    display_name: 'OpenAI',
    target: 'https://api.openai.com',
    description: 'OpenAI API',
    auth_methods: [
      {
        id: 'openai_key',
        name: 'API Key',
        description: 'OpenAI key',
        fields: [{ key: 'token', label: 'API Key', type: 'password', required: true }],
        injection: { type: 'bearer_header' },
      },
    ],
  },
];

describe('TemplatePicker - rendering', () => {
  it('renders all provided templates', () => {
    render(
      <TemplatePicker
        templates={MOCK_TEMPLATES}
        onSelect={vi.fn()}
        onSelectCustom={vi.fn()}
      />
    );
    expect(screen.getByText('Stripe')).toBeInTheDocument();
    expect(screen.getByText('GitHub')).toBeInTheDocument();
    expect(screen.getByText('OpenAI')).toBeInTheDocument();
  });

  it('renders a "Custom Service" option', () => {
    render(
      <TemplatePicker
        templates={MOCK_TEMPLATES}
        onSelect={vi.fn()}
        onSelectCustom={vi.fn()}
      />
    );
    expect(screen.getByText(/custom service/i)).toBeInTheDocument();
  });

  it('renders template descriptions when provided', () => {
    render(
      <TemplatePicker
        templates={MOCK_TEMPLATES}
        onSelect={vi.fn()}
        onSelectCustom={vi.fn()}
      />
    );
    expect(screen.getByText('Stripe payment API')).toBeInTheDocument();
  });

  it('renders service icon or letter avatar for each template', () => {
    const { container } = render(
      <TemplatePicker
        templates={MOCK_TEMPLATES}
        onSelect={vi.fn()}
        onSelectCustom={vi.fn()}
      />
    );
    // Should have rendered something for each template
    expect(container.querySelectorAll('button').length).toBeGreaterThan(0);
  });

  it('renders empty state when no templates provided', () => {
    render(
      <TemplatePicker
        templates={[]}
        onSelect={vi.fn()}
        onSelectCustom={vi.fn()}
      />
    );
    // Custom service should still be shown
    expect(screen.getByText(/custom service/i)).toBeInTheDocument();
  });
});

describe('TemplatePicker - interaction', () => {
  it('calls onSelect with the template when a template tile is clicked', () => {
    const onSelect = vi.fn();
    render(
      <TemplatePicker
        templates={MOCK_TEMPLATES}
        onSelect={onSelect}
        onSelectCustom={vi.fn()}
      />
    );
    fireEvent.click(screen.getByText('Stripe'));
    expect(onSelect).toHaveBeenCalledWith(MOCK_TEMPLATES[0]);
  });

  it('calls onSelectCustom when Custom Service tile is clicked', () => {
    const onSelectCustom = vi.fn();
    render(
      <TemplatePicker
        templates={MOCK_TEMPLATES}
        onSelect={vi.fn()}
        onSelectCustom={onSelectCustom}
      />
    );
    fireEvent.click(screen.getByText(/custom service/i));
    expect(onSelectCustom).toHaveBeenCalledTimes(1);
  });

  it('calls onSelect with the correct template for each tile', () => {
    const onSelect = vi.fn();
    render(
      <TemplatePicker
        templates={MOCK_TEMPLATES}
        onSelect={onSelect}
        onSelectCustom={vi.fn()}
      />
    );
    fireEvent.click(screen.getByText('GitHub'));
    expect(onSelect).toHaveBeenCalledWith(MOCK_TEMPLATES[1]);
  });
});
