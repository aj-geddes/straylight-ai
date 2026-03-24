import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { Layout } from '../components/Layout';

describe('Layout', () => {
  it('renders the Straylight-AI brand name', () => {
    render(<Layout><div>content</div></Layout>);
    expect(screen.getByText('Straylight-AI')).toBeInTheDocument();
  });

  it('renders the tagline', () => {
    render(<Layout><div>content</div></Layout>);
    expect(screen.getByText(/use ai, with zero trust/i)).toBeInTheDocument();
  });

  it('renders the navigation with Dashboard link', () => {
    render(<Layout><div>content</div></Layout>);
    expect(screen.getByRole('link', { name: /dashboard/i })).toBeInTheDocument();
  });

  it('renders the navigation with Services link', () => {
    render(<Layout><div>content</div></Layout>);
    expect(screen.getByRole('link', { name: /services/i })).toBeInTheDocument();
  });

  it('renders children in the main content area', () => {
    render(<Layout><p>test content</p></Layout>);
    expect(screen.getByText('test content')).toBeInTheDocument();
  });

  it('marks the current page with aria-current', () => {
    render(<Layout currentPath="/"><div>content</div></Layout>);
    const dashboardLink = screen.getByRole('link', { name: /dashboard/i });
    expect(dashboardLink).toHaveAttribute('aria-current', 'page');
  });

  it('does not mark non-current page with aria-current', () => {
    render(<Layout currentPath="/"><div>content</div></Layout>);
    const servicesLink = screen.getByRole('link', { name: /services/i });
    expect(servicesLink).not.toHaveAttribute('aria-current', 'page');
  });

  it('renders the main navigation landmark', () => {
    render(<Layout><div>content</div></Layout>);
    expect(screen.getByRole('navigation', { name: /main navigation/i })).toBeInTheDocument();
  });
});
