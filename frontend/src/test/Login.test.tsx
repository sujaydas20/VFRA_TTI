import { describe, it, expect } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { Login } from '../pages/Login';

describe('Login Page', () => {
  it('renders login form elements and cyber-defense branding', () => {
    render(
      <MemoryRouter>
        <Login />
      </MemoryRouter>
    );

    expect(screen.getByText('Telegram Threat Intelligence')).toBeInTheDocument();
    expect(screen.getByText('Investigator Sign In')).toBeInTheDocument();
    expect(screen.getByPlaceholderText('analyst@example.com')).toBeInTheDocument();
    expect(screen.getByPlaceholderText('••••••••')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /sign in/i })).toBeInTheDocument();
  });

  it('populates credentials when clicking Auto-fill Demo', () => {
    render(
      <MemoryRouter>
        <Login />
      </MemoryRouter>
    );

    const autoFillBtn = screen.getByRole('button', { name: /auto-fill demo/i });
    fireEvent.click(autoFillBtn);

    const emailInput = screen.getByPlaceholderText('analyst@example.com') as HTMLInputElement;
    const passInput = screen.getByPlaceholderText('••••••••') as HTMLInputElement;

    expect(emailInput.value).toBe('analyst@example.com');
    expect(passInput.value).toBe('demo-pass');
  });

  it('displays authentication error banner on invalid credentials without navigating', async () => {
    render(
      <MemoryRouter>
        <Login />
      </MemoryRouter>
    );

    const emailInput = screen.getByPlaceholderText('analyst@example.com');
    const passInput = screen.getByPlaceholderText('••••••••');
    const submitBtn = screen.getByRole('button', { name: /sign in/i });

    fireEvent.change(emailInput, { target: { value: 'wrong@example.com' } });
    fireEvent.change(passInput, { target: { value: 'bad-password' } });
    fireEvent.click(submitBtn);

    await waitFor(() => {
      expect(screen.getByText(/Invalid email address or password/i)).toBeInTheDocument();
    });
  });
});
