import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { Help } from '../pages/Help';

describe('Help page - sections', () => {
  it('renders Getting Started section', () => {
    render(<Help />);
    expect(screen.getAllByText(/getting started/i).length).toBeGreaterThan(0);
  });

  it('renders MCP Integration section', () => {
    render(<Help />);
    expect(screen.getAllByText(/mcp integration/i).length).toBeGreaterThan(0);
  });

  it('renders Supported Services section', () => {
    render(<Help />);
    expect(screen.getAllByText(/supported services/i).length).toBeGreaterThan(0);
  });

  it('renders FAQ section', () => {
    render(<Help />);
    expect(screen.getAllByText(/faq/i).length).toBeGreaterThan(0);
  });

  it('renders Troubleshooting section', () => {
    render(<Help />);
    expect(screen.getAllByText(/troubleshooting/i).length).toBeGreaterThan(0);
  });
});

describe('Help page - content', () => {
  it('shows claude mcp add command', () => {
    render(<Help />);
    expect(screen.getAllByText(/claude mcp add/i).length).toBeGreaterThan(0);
  });

  it('lists GitHub as a supported service with link', () => {
    render(<Help />);
    const githubLink = screen.getByRole('link', { name: /github/i });
    expect(githubLink).toBeInTheDocument();
    expect(githubLink).toHaveAttribute('href', expect.stringContaining('github.com'));
  });

  it('lists OpenAI as a supported service with link', () => {
    render(<Help />);
    const openaiLink = screen.getByRole('link', { name: /openai/i });
    expect(openaiLink).toBeInTheDocument();
    expect(openaiLink).toHaveAttribute('href', expect.stringContaining('openai.com'));
  });

  it('lists Anthropic as a supported service with link', () => {
    render(<Help />);
    const anthropicLink = screen.getByRole('link', { name: /anthropic/i });
    expect(anthropicLink).toBeInTheDocument();
    expect(anthropicLink).toHaveAttribute('href', expect.stringContaining('anthropic.com'));
  });

  it('lists Stripe as a supported service with link', () => {
    render(<Help />);
    const stripeLink = screen.getByRole('link', { name: /stripe/i });
    expect(stripeLink).toBeInTheDocument();
    expect(stripeLink).toHaveAttribute('href', expect.stringContaining('stripe.com'));
  });

  it('lists Slack as a supported service with link', () => {
    render(<Help />);
    const slackLink = screen.getByRole('link', { name: /slack/i });
    expect(slackLink).toBeInTheDocument();
    expect(slackLink).toHaveAttribute('href', expect.stringContaining('slack.com'));
  });

  it('shows Getting Started 3-step guide', () => {
    render(<Help />);
    expect(screen.getByText(/install straylight/i)).toBeInTheDocument();
  });

  it('renders search input', () => {
    render(<Help />);
    expect(screen.getByPlaceholderText(/search help/i)).toBeInTheDocument();
  });

  it('renders Key Concepts section', () => {
    render(<Help />);
    expect(screen.getAllByText(/key concepts/i).length).toBeGreaterThan(0);
  });
});

describe('Help page - navigation', () => {
  it('renders page with a main heading', () => {
    render(<Help />);
    expect(screen.getByRole('heading', { level: 1 })).toBeInTheDocument();
  });
});
