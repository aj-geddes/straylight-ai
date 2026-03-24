import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { DeviceFlowStep } from '../components/DeviceFlowStep';

// Mock the API client
vi.mock('../api/client', () => ({
  startDeviceFlow: vi.fn(),
  pollDeviceFlow: vi.fn(),
}));

import { startDeviceFlow, pollDeviceFlow } from '../api/client';

const DEFAULT_DEVICE_RESPONSE = {
  device_code: 'DEV_CODE_123',
  user_code: 'ABCD-1234',
  verification_uri: 'https://github.com/login/device',
  expires_in: 900,
  interval: 5,
};

describe('DeviceFlowStep - initial state', () => {
  afterEach(() => vi.clearAllMocks());

  it('renders the Start Authorization button initially', () => {
    render(
      <DeviceFlowStep
        provider="github"
        displayName="GitHub"
        serviceName="my-github"
        onSuccess={vi.fn()}
      />
    );
    expect(screen.getByRole('button', { name: /start authorization/i })).toBeInTheDocument();
  });

  it('shows instructional text about the flow', () => {
    render(
      <DeviceFlowStep
        provider="github"
        displayName="GitHub"
        serviceName="my-github"
        onSuccess={vi.fn()}
      />
    );
    expect(screen.getByText(/github\.com\/login\/device/i)).toBeInTheDocument();
  });

  it('shows the GitHub provider name', () => {
    render(
      <DeviceFlowStep
        provider="github"
        displayName="GitHub"
        serviceName="my-github"
        onSuccess={vi.fn()}
      />
    );
    expect(screen.getByText(/connect with github/i)).toBeInTheDocument();
  });
});

describe('DeviceFlowStep - after starting authorization', () => {
  beforeEach(() => {
    vi.mocked(startDeviceFlow).mockResolvedValue(DEFAULT_DEVICE_RESPONSE);
    vi.mocked(pollDeviceFlow).mockResolvedValue({ status: 'pending' });
  });

  afterEach(() => vi.clearAllMocks());

  it('shows the user code prominently after starting', async () => {
    const user = userEvent.setup({ delay: null });
    render(
      <DeviceFlowStep
        provider="github"
        displayName="GitHub"
        serviceName="my-github"
        onSuccess={vi.fn()}
      />
    );

    await user.click(screen.getByRole('button', { name: /start authorization/i }));

    await waitFor(() => {
      expect(screen.getByText('ABCD-1234')).toBeInTheDocument();
    });
  });

  it('shows a link to github.com/login/device', async () => {
    const user = userEvent.setup({ delay: null });
    render(
      <DeviceFlowStep
        provider="github"
        displayName="GitHub"
        serviceName="my-github"
        onSuccess={vi.fn()}
      />
    );

    await user.click(screen.getByRole('button', { name: /start authorization/i }));

    await waitFor(() => {
      const link = screen.getByRole('link', { name: /github\.com\/login\/device/i });
      expect(link).toBeInTheDocument();
      expect(link).toHaveAttribute('href', 'https://github.com/login/device');
    });
  });

  it('shows waiting for authorization text', async () => {
    const user = userEvent.setup({ delay: null });
    render(
      <DeviceFlowStep
        provider="github"
        displayName="GitHub"
        serviceName="my-github"
        onSuccess={vi.fn()}
      />
    );

    await user.click(screen.getByRole('button', { name: /start authorization/i }));

    await waitFor(() => {
      expect(screen.getByText(/waiting for authorization/i)).toBeInTheDocument();
    });
  });

  it('calls startDeviceFlow with the correct provider and service name', async () => {
    const user = userEvent.setup({ delay: null });
    render(
      <DeviceFlowStep
        provider="github"
        displayName="GitHub"
        serviceName="my-github"
        onSuccess={vi.fn()}
      />
    );

    await user.click(screen.getByRole('button', { name: /start authorization/i }));

    await waitFor(() => {
      expect(startDeviceFlow).toHaveBeenCalledWith('github', 'my-github');
    });
  });
});

describe('DeviceFlowStep - polling', () => {
  afterEach(() => vi.clearAllMocks());

  it('calls pollDeviceFlow with device code and service name', async () => {
    const user = userEvent.setup({ delay: null });
    vi.mocked(startDeviceFlow).mockResolvedValue(DEFAULT_DEVICE_RESPONSE);
    vi.mocked(pollDeviceFlow).mockResolvedValue({ status: 'pending' });

    render(
      <DeviceFlowStep
        provider="github"
        displayName="GitHub"
        serviceName="my-github"
        onSuccess={vi.fn()}
        _testPollIntervalMs={0}
      />
    );

    await user.click(screen.getByRole('button', { name: /start authorization/i }));

    await waitFor(() => {
      expect(pollDeviceFlow).toHaveBeenCalledWith(
        'github',
        'DEV_CODE_123',
        'my-github'
      );
    });
  });

  it('calls onSuccess when poll returns complete', async () => {
    const user = userEvent.setup({ delay: null });
    const onSuccess = vi.fn();

    vi.mocked(startDeviceFlow).mockResolvedValue(DEFAULT_DEVICE_RESPONSE);
    vi.mocked(pollDeviceFlow).mockResolvedValue({ status: 'complete' });

    render(
      <DeviceFlowStep
        provider="github"
        displayName="GitHub"
        serviceName="my-github"
        onSuccess={onSuccess}
        _testPollIntervalMs={0}
      />
    );

    await user.click(screen.getByRole('button', { name: /start authorization/i }));

    await waitFor(() => {
      expect(onSuccess).toHaveBeenCalledTimes(1);
    });
  });

  it('shows expired message when poll returns expired', async () => {
    const user = userEvent.setup({ delay: null });
    vi.mocked(startDeviceFlow).mockResolvedValue(DEFAULT_DEVICE_RESPONSE);
    vi.mocked(pollDeviceFlow).mockResolvedValue({ status: 'expired' });

    render(
      <DeviceFlowStep
        provider="github"
        displayName="GitHub"
        serviceName="my-github"
        onSuccess={vi.fn()}
        _testPollIntervalMs={0}
      />
    );

    await user.click(screen.getByRole('button', { name: /start authorization/i }));

    await waitFor(() => {
      expect(screen.getByText(/expired/i)).toBeInTheDocument();
    });
  });

  it('shows a try again button when code has expired', async () => {
    const user = userEvent.setup({ delay: null });
    vi.mocked(startDeviceFlow).mockResolvedValue(DEFAULT_DEVICE_RESPONSE);
    vi.mocked(pollDeviceFlow).mockResolvedValue({ status: 'expired' });

    render(
      <DeviceFlowStep
        provider="github"
        displayName="GitHub"
        serviceName="my-github"
        onSuccess={vi.fn()}
        _testPollIntervalMs={0}
      />
    );

    await user.click(screen.getByRole('button', { name: /start authorization/i }));

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /try again/i })).toBeInTheDocument();
    });
  });
});

describe('DeviceFlowStep - error handling', () => {
  afterEach(() => vi.clearAllMocks());

  it('shows error message when startDeviceFlow fails', async () => {
    const user = userEvent.setup({ delay: null });
    vi.mocked(startDeviceFlow).mockRejectedValue(new Error('client_id not configured'));

    render(
      <DeviceFlowStep
        provider="github"
        displayName="GitHub"
        serviceName="my-github"
        onSuccess={vi.fn()}
      />
    );

    await user.click(screen.getByRole('button', { name: /start authorization/i }));

    await waitFor(() => {
      expect(screen.getByText(/client_id not configured/i)).toBeInTheDocument();
    });
  });

  it('shows Start Authorization button again after error', async () => {
    const user = userEvent.setup({ delay: null });
    vi.mocked(startDeviceFlow).mockRejectedValue(new Error('Network error'));

    render(
      <DeviceFlowStep
        provider="github"
        displayName="GitHub"
        serviceName="my-github"
        onSuccess={vi.fn()}
      />
    );

    await user.click(screen.getByRole('button', { name: /start authorization/i }));

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /start authorization/i })).toBeInTheDocument();
    });
  });
});

describe('DeviceFlowStep - connected success state', () => {
  afterEach(() => vi.clearAllMocks());

  it('shows connected message when authorization is complete', async () => {
    const user = userEvent.setup({ delay: null });
    vi.mocked(startDeviceFlow).mockResolvedValue(DEFAULT_DEVICE_RESPONSE);
    vi.mocked(pollDeviceFlow).mockResolvedValue({ status: 'complete' });

    render(
      <DeviceFlowStep
        provider="github"
        displayName="GitHub"
        serviceName="my-github"
        onSuccess={vi.fn()}
        _testPollIntervalMs={0}
      />
    );

    await user.click(screen.getByRole('button', { name: /start authorization/i }));

    await waitFor(() => {
      expect(screen.getByText(/connected/i)).toBeInTheDocument();
    });
  });
});
