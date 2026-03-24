import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { Help } from '../pages/Help';

describe('Help page - sections', () => {
  it('renders Getting Started section', () => {
    render(<Help />);
    expect(screen.getByText(/getting started/i)).toBeInTheDocument();
  });

  it('renders MCP Integration section', () => {
    render(<Help />);
    expect(screen.getByText(/mcp integration/i)).toBeInTheDocument();
  });

  it('renders Supported Services section', () => {
    render(<Help />);
    expect(screen.getByText(/supported services/i)).toBeInTheDocument();
  });

  it('renders FAQ section', () => {
    render(<Help />);
    expect(screen.getByText(/faq/i)).toBeInTheDocument();
  });

  it('renders Troubleshooting section', () => {
    render(<Help />);
    expect(screen.getByText(/troubleshooting/i)).toBeInTheDocument();
  });
});

describe('Help page - content', () => {
  it('shows claude mcp add command', () => {
    render(<Help />);
    // The command appears in a <code> element inside <pre>
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
    // Should contain numbered steps (step 1, step 2, step 3)
    expect(screen.getByText(/step 1|1\./i)).toBeInTheDocument();
  });
});

describe('Help page - navigation', () => {
  it('renders page with a main heading', () => {
    render(<Help />);
    expect(screen.getByRole('heading', { level: 1 })).toBeInTheDocument();
  });
});
