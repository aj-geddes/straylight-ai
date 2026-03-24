import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { ServiceIcon } from '../components/ServiceIcon';

describe('ServiceIcon - known services', () => {
  it('renders svg for github', () => {
    const { container } = render(<ServiceIcon name="github" size={24} />);
    expect(container.querySelector('svg')).toBeInTheDocument();
  });

  it('renders svg for stripe', () => {
    const { container } = render(<ServiceIcon name="stripe" size={24} />);
    expect(container.querySelector('svg')).toBeInTheDocument();
  });

  it('renders svg for openai', () => {
    const { container } = render(<ServiceIcon name="openai" size={24} />);
    expect(container.querySelector('svg')).toBeInTheDocument();
  });

  it('renders svg for anthropic', () => {
    const { container } = render(<ServiceIcon name="anthropic" size={24} />);
    expect(container.querySelector('svg')).toBeInTheDocument();
  });
});

describe('ServiceIcon - fallback', () => {
  it('renders a letter avatar for unknown service names', () => {
    render(<ServiceIcon name="myservice" size={24} />);
    expect(screen.getByText('M')).toBeInTheDocument();
  });

  it('renders uppercase first letter for fallback', () => {
    render(<ServiceIcon name="zippy" size={24} />);
    expect(screen.getByText('Z')).toBeInTheDocument();
  });

  it('renders fallback for empty string', () => {
    render(<ServiceIcon name="" size={24} />);
    expect(screen.getByText('?')).toBeInTheDocument();
  });
});

describe('ServiceIcon - size prop', () => {
  it('applies the size to the container', () => {
    const { container } = render(<ServiceIcon name="github" size={32} />);
    const wrapper = container.firstChild as HTMLElement;
    expect(wrapper).toBeTruthy();
  });
});
