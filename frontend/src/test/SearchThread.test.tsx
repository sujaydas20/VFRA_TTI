import { describe, it, expect } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { SearchThreadDetail } from '../pages/SearchThreadDetail';

describe('SearchThreadDetail Component (Phase 3 Search)', () => {
  it('renders search bar and lists sanitized threat observables', async () => {
    render(
      <MemoryRouter>
        <SearchThreadDetail />
      </MemoryRouter>
    );

    expect(screen.getByText('Observable Search & Thread Explorer')).toBeInTheDocument();
    expect(screen.getByPlaceholderText(/search threat messages/i)).toBeInTheDocument();

    await waitFor(() => {
      // Look for sanitized message content
      expect(screen.getByText(/Fresh corporate VPN access dump/i)).toBeInTheDocument();
      // Look for defanged observable flags
      expect(screen.getAllByText('[DEFANGED_URL]').length).toBeGreaterThanOrEqual(1);
    });
  });
});
