import React from 'react';

export const ArchitectureOverview: React.FC = () => {
  return (
    <div className="security-card">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.5rem' }}>
        <h2 style={{ fontSize: '1.1rem', fontWeight: 600, color: 'var(--text-primary)' }}>
          🔒 Phase 1 Security & Engineering Baseline
        </h2>
        <span className="badge badge-cyan">Zero-Trust Untrusted Inputs</span>
      </div>

      <ul className="rule-list">
        <li className="rule-item">
          <strong>Tenant Isolation Enforced</strong>
          All intelligence data models and evidence artifacts mandate <code>tenant_id</code> scoping from Day 1. Cross-tenant leakage is strictly prevented.
        </li>
        <li className="rule-item">
          <strong>Inert Connector Boundary</strong>
          Telegram and dark-web connectors are isolated behind modular interfaces. Live collection is strictly deactivated in Phase 1.
        </li>
        <li className="rule-item">
          <strong>Untrusted Input Sanitization</strong>
          All scraped payloads pass through <code>InputSanitizer</code> to redact embedded scripts, strip control bytes, and defang dangerous URI schemes.
        </li>
        <li className="rule-item">
          <strong>Physical Evidence Segregation</strong>
          Raw evidence storage is strictly separated from public frontend static assets and verified via cryptographic SHA-256 hashes.
        </li>
        <li className="rule-item">
          <strong>No Autonomous Action Proliferation</strong>
          Unrestricted autonomous actions and live reinforcement learning are strictly disabled. Decisions require human analyst validation.
        </li>
        <li className="rule-item">
          <strong>Backend-Enforced Authorization</strong>
          Tenant context and access control are validated on the backend API, never trusted merely from client-side state.
        </li>
      </ul>
    </div>
  );
};
