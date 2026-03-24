import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { StatusIndicator } from '../components/StatusIndicator';

describe('StatusIndicator', () => {
  it('renders a green dot for ok status', () => {
    render(<StatusIndicator status="ok" />);
    const dot = screen.getByRole('img', { hidden: true });
    expect(dot).toHaveClass('bg-emerald-500');
  });

  it('renders a yellow dot for starting status', () => {
    render(<StatusIndicator status="starting" />);
    const dot = screen.getByRole('img', { hidden: true });
    expect(dot).toHaveClass('bg-amber-400');
  });

  it('renders a red dot for degraded status', () => {
    render(<StatusIndicator status="degraded" />);
    const dot = screen.getByRole('img', { hidden: true });
    expect(dot).toHaveClass('bg-red-500');
  });

  it('renders with accessible label', () => {
    render(<StatusIndicator status="ok" label="OpenBao status" />);
    expect(screen.getByTitle('OpenBao status')).toBeInTheDocument();
  });
});
