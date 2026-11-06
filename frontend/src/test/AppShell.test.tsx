import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { MemoryRouter, Routes, Route } from 'react-router-dom';
import { AppShell } from '../components/AppShell';

describe('AppShell Layout Component', () => {
  it('renders persistent navigation sidebar and operations topnav', () => {
    render(
      <MemoryRouter initialEntries={['/test']}>
        <Routes>
          <Route element={<AppShell />}>
            <Route path="/test" element={<div data-testid="test-content">Dashboard Active</div>} />
          </Route>
        </Routes>
      </MemoryRouter>
    );

    // Sidebar branding & tenant header
    expect(screen.getAllByText('Threat Intelligence').length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText('Acme Cyber Defense')).toBeInTheDocument();
    expect(screen.getByText('Enterprise CTI Suite')).toBeInTheDocument();

    // TopNav status
    expect(screen.getByText('TTI Operations')).toBeInTheDocument();
    expect(screen.getByText('Tenant: tenant_00000001')).toBeInTheDocument();

    // Navigation links
    expect(screen.getByText('Overview & Feeds')).toBeInTheDocument();
    expect(screen.getByText('Channel Management')).toBeInTheDocument();
    expect(screen.getByText('Search & Threads')).toBeInTheDocument();
    expect(screen.getByText('Audit Log Viewer')).toBeInTheDocument();

    // Content outlet
    expect(screen.getByTestId('test-content')).toBeInTheDocument();
  });
});
