import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { HealthBadge } from '../components/HealthBadge';

describe('HealthBadge Component', () => {
  it('renders "Online" badge for healthy status', () => {
    render(<HealthBadge status="healthy" />);
    expect(screen.getByText('Online')).toBeInTheDocument();
    expect(screen.getByText('Online')).toHaveClass('badge-emerald');
  });

  it('renders "Degraded" badge for degraded status', () => {
    render(<HealthBadge status="degraded" />);
    expect(screen.getByText('Degraded')).toBeInTheDocument();
    expect(screen.getByText('Degraded')).toHaveClass('badge-amber');
  });

  it('renders "Inert / Safe" badge for disabled status per DEC-02', () => {
    render(<HealthBadge status="disabled" />);
    expect(screen.getByText('Inert / Safe')).toBeInTheDocument();
    expect(screen.getByText('Inert / Safe')).toHaveClass('badge-purple');
  });

  it('renders "Offline" badge for unavailable and disconnected status', () => {
    const { rerender } = render(<HealthBadge status="unavailable" />);
    expect(screen.getByText('Offline')).toBeInTheDocument();

    rerender(<HealthBadge status="disconnected" />);
    expect(screen.getByText('Offline')).toBeInTheDocument();
  });
});
