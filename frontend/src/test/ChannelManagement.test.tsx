import { describe, it, expect } from 'vitest';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { ChannelManagement } from '../pages/ChannelManagement';

describe('ChannelManagement Component (SEC-THREAT-05)', () => {
  it('renders channel administration view with security invariant notice', async () => {
    render(
      <MemoryRouter>
        <ChannelManagement />
      </MemoryRouter>
    );

    expect(screen.getByText('Source Channel Administration')).toBeInTheDocument();
    expect(screen.getByText(/SEC-THREAT-01 & SEC-THREAT-05 Invariants/i)).toBeInTheDocument();

    await waitFor(() => {
      expect(screen.getByText('ShadowMarket Leak Hub')).toBeInTheDocument();
      expect(screen.getByText('Crypto Drainers & Phish Feed')).toBeInTheDocument();
    });
  });

  it('opens registration modal with default unauthorized security state', async () => {
    render(
      <MemoryRouter>
        <ChannelManagement />
      </MemoryRouter>
    );

    const registerBtn = screen.getByRole('button', { name: /register source channel/i });
    fireEvent.click(registerBtn);

    expect(screen.getByText('Register Intelligence Source Channel')).toBeInTheDocument();
    expect(screen.getByPlaceholderText('e.g. tg_market_intel_01')).toBeInTheDocument();
  });
});
