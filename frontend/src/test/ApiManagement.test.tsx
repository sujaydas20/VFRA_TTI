import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { ApiManagement } from '../pages/ApiManagement';

describe('ApiManagement Component', () => {
  it('renders the API inventory page header without crashing', async () => {
    render(
      <MemoryRouter>
        <ApiManagement />
      </MemoryRouter>,
    );

    // Header renders immediately (title also appears in breadcrumb, so scope to heading).
    expect(screen.getByRole('heading', { name: /API Management/i })).toBeInTheDocument();
    expect(screen.getByText(/Automatic discovery/i)).toBeInTheDocument();
  });
});