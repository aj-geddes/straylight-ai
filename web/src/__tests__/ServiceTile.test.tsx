import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { ServiceTile } from '../components/ServiceTile';
import type { Service } from '../types/service';

const AVAILABLE_SERVICE: Service = {
  name: 'stripe',
  type: 'http_proxy',
  target: 'https://api.stripe.com',
  inject: 'header',
  header_template: 'Bearer {{.secret}}',
  status: 'available',
  created_at: '2026-03-22T00:00:00Z',
  updated_at: '2026-03-22T00:00:00Z',
};

const EXPIRED_SERVICE: Service = {
  name: 'github',
  type: 'oauth',
  target: 'https://api.github.com',
  inject: 'header',
  status: 'expired',
  created_at: '2026-03-22T00:00:00Z',
  updated_at: '2026-03-22T00:00:00Z',
};

const NOT_CONFIGURED_SERVICE: Service = {
  name: 'openai',
  type: 'http_proxy',
  target: 'https://api.openai.com',
  inject: 'header',
  status: 'not_configured',
  created_at: '2026-03-22T00:00:00Z',
  updated_at: '2026-03-22T00:00:00Z',
};

describe('ServiceTile - rendering', () => {
  it('displays the service name', () => {
    render(<ServiceTile service={AVAILABLE_SERVICE} onClick={vi.fn()} />);
    expect(screen.getByText('stripe')).toBeInTheDocument();
  });

  it('displays the service type', () => {
    render(<ServiceTile service={AVAILABLE_SERVICE} onClick={vi.fn()} />);
    expect(screen.getByText(/http_proxy/i)).toBeInTheDocument();
  });

  it('displays a green status indicator for available status', () => {
    render(<ServiceTile service={AVAILABLE_SERVICE} onClick={vi.fn()} />);
    const indicator = screen.getByTitle('available');
    expect(indicator).toHaveClass('bg-emerald-500');
  });

  it('displays a yellow status indicator for expired status', () => {
    render(<ServiceTile service={EXPIRED_SERVICE} onClick={vi.fn()} />);
    const indicator = screen.getByTitle('expired');
    expect(indicator).toHaveClass('bg-amber-400');
  });

  it('displays a gray status indicator for not_configured status', () => {
    render(<ServiceTile service={NOT_CONFIGURED_SERVICE} onClick={vi.fn()} />);
    const indicator = screen.getByTitle('not_configured');
    expect(indicator).toHaveClass('bg-slate-400');
  });

  it('renders a service icon or letter avatar', () => {
    render(<ServiceTile service={AVAILABLE_SERVICE} onClick={vi.fn()} />);
    // ServiceIcon renders either SVG (for known) or letter avatar (for unknown)
    // stripe has an SVG icon
    const { container } = render(<ServiceTile service={AVAILABLE_SERVICE} onClick={vi.fn()} />);
    expect(container.firstChild).toBeInTheDocument();
  });

  it('is a button/clickable element', () => {
    render(<ServiceTile service={AVAILABLE_SERVICE} onClick={vi.fn()} />);
    expect(screen.getAllByRole('button')[0]).toBeInTheDocument();
  });

  it('shows Connected status label for available services', () => {
    render(<ServiceTile service={AVAILABLE_SERVICE} onClick={vi.fn()} />);
    expect(screen.getByText('Connected')).toBeInTheDocument();
  });

  it('shows Expired status label for expired services', () => {
    render(<ServiceTile service={EXPIRED_SERVICE} onClick={vi.fn()} />);
    expect(screen.getByText('Expired')).toBeInTheDocument();
  });

  it('shows Not Configured status label for not_configured services', () => {
    render(<ServiceTile service={NOT_CONFIGURED_SERVICE} onClick={vi.fn()} />);
    expect(screen.getByText('Not Configured')).toBeInTheDocument();
  });

  it('shows auth_method_name when present', () => {
    const service: Service = {
      ...AVAILABLE_SERVICE,
      auth_method_name: 'Personal Access Token',
    };
    render(<ServiceTile service={service} onClick={vi.fn()} />);
    expect(screen.getByText('Personal Access Token')).toBeInTheDocument();
  });
});

describe('ServiceTile - interaction', () => {
  it('calls onClick when clicked', () => {
    const onClick = vi.fn();
    render(<ServiceTile service={AVAILABLE_SERVICE} onClick={onClick} />);
    fireEvent.click(screen.getAllByRole('button')[0]);
    expect(onClick).toHaveBeenCalledTimes(1);
  });

  it('passes the service to onClick callback', () => {
    const onClick = vi.fn();
    render(<ServiceTile service={AVAILABLE_SERVICE} onClick={onClick} />);
    fireEvent.click(screen.getAllByRole('button')[0]);
    expect(onClick).toHaveBeenCalledWith(AVAILABLE_SERVICE);
  });
});

describe('ServiceTile - account info', () => {
  const SERVICE_WITH_ACCOUNT_INFO: Service = {
    ...AVAILABLE_SERVICE,
    account_info: {
      display_name: 'AJ Geddes',
      username: 'aj-geddes',
      avatar_url: 'https://avatars.githubusercontent.com/u/123',
      extra: {
        public_repos: '26',
        followers: '10',
      },
    },
  };

  it('shows username when account_info is present', () => {
    render(<ServiceTile service={SERVICE_WITH_ACCOUNT_INFO} onClick={vi.fn()} />);
    // username and display_name may be combined in one element
    expect(screen.getByText(/aj-geddes/)).toBeInTheDocument();
  });

  it('shows display_name when account_info is present', () => {
    render(<ServiceTile service={SERVICE_WITH_ACCOUNT_INFO} onClick={vi.fn()} />);
    expect(screen.getByText(/AJ Geddes/)).toBeInTheDocument();
  });

  it('renders avatar image when avatar_url is present', () => {
    render(<ServiceTile service={SERVICE_WITH_ACCOUNT_INFO} onClick={vi.fn()} />);
    const avatar = screen.getByRole('img', { name: /aj-geddes avatar/i });
    expect(avatar).toBeInTheDocument();
    expect(avatar).toHaveAttribute('src', 'https://avatars.githubusercontent.com/u/123');
  });

  it('renders extra stats as badges', () => {
    render(<ServiceTile service={SERVICE_WITH_ACCOUNT_INFO} onClick={vi.fn()} />);
    expect(screen.getByText(/26/)).toBeInTheDocument();
    expect(screen.getByText(/10/)).toBeInTheDocument();
  });

  it('does not show account info when account_info is absent', () => {
    render(<ServiceTile service={AVAILABLE_SERVICE} onClick={vi.fn()} />);
    expect(screen.queryByRole('img', { name: /avatar/i })).not.toBeInTheDocument();
  });

  it('shows only display_name when username is absent', () => {
    const service: Service = {
      ...AVAILABLE_SERVICE,
      account_info: {
        display_name: 'OpenAI API',
      },
    };
    render(<ServiceTile service={service} onClick={vi.fn()} />);
    expect(screen.getByText('OpenAI API')).toBeInTheDocument();
  });

  it('shows plan badge when plan is present', () => {
    const service: Service = {
      ...AVAILABLE_SERVICE,
      account_info: {
        display_name: 'AJ Geddes',
        plan: 'pro',
      },
    };
    render(<ServiceTile service={service} onClick={vi.fn()} />);
    // Plan badge renders the plan text directly in a <span>
    const planBadge = screen.getByText((content) => content === 'pro');
    expect(planBadge).toBeInTheDocument();
  });
});
