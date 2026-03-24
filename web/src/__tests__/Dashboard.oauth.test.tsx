import { describe, it, expect, vi, afterEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { Dashboard } from '../pages/Dashboard';

vi.mock('../api/client', () => ({
  getHealth: vi.fn().mockResolvedValue({ status: 'ok', openbao: 'unsealed', version: '0.1.0' }),
  getServices: vi.fn().mockResolvedValue([]),
  getTemplates: vi.fn().mockResolvedValue([]),
  addServiceFromTemplate: vi.fn(),
}));

// Mock window.location for URL param reading
const originalLocation = window.location;

describe('Dashboard - OAuth success handling', () => {
  afterEach(() => {
    vi.clearAllMocks();
    // Restore location
    Object.defineProperty(window, 'location', {
      value: originalLocation,
      writable: true,
    });
  });

  it('shows success banner when oauth=success param is in URL', async () => {
    Object.defineProperty(window, 'location', {
      value: {
        ...originalLocation,
        search: '?oauth=success&service=github',
        href: 'http://localhost/?oauth=success&service=github',
      },
      writable: true,
    });

    render(<Dashboard />);

    await waitFor(() => {
      expect(screen.getByText(/successfully connected/i)).toBeInTheDocument();
    });
  });

  it('includes the service name in the success banner', async () => {
    Object.defineProperty(window, 'location', {
      value: {
        ...originalLocation,
        search: '?oauth=success&service=mygithub',
        href: 'http://localhost/?oauth=success&service=mygithub',
      },
      writable: true,
    });

    render(<Dashboard />);

    await waitFor(() => {
      expect(screen.getByText(/mygithub/i)).toBeInTheDocument();
    });
  });

  it('does not show success banner without oauth param', async () => {
    Object.defineProperty(window, 'location', {
      value: {
        ...originalLocation,
        search: '',
        href: 'http://localhost/',
      },
      writable: true,
    });

    render(<Dashboard />);

    // Wait briefly and confirm no success banner
    await waitFor(() => {
      expect(screen.queryByText(/successfully connected/i)).not.toBeInTheDocument();
    });
  });
});
