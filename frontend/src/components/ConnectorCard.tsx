import React from 'react';
import { ConnectorHealth } from '../types';
import { HealthBadge } from './HealthBadge';

interface ConnectorCardProps {
  connector: ConnectorHealth;
  title: string;
  sourceType: 'telegram' | 'darkweb';
}

export const ConnectorCard: React.FC<ConnectorCardProps> = ({ connector, title, sourceType }) => {
  const icon = sourceType === 'telegram' ? '📱' : '🧅';

  return (
    <div className="card">
      <div>
        <div className="card-header">
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <span style={{ fontSize: '1.25rem' }}>{icon}</span>
            <span className="card-title">{title}</span>
          </div>
          <HealthBadge status={connector.status} />
        </div>
        <p className="card-desc">{connector.message}</p>
      </div>

      <div className="card-footer">
        <span>Rate Limit: {connector.rate_limit_remaining ?? 'N/A'}</span>
        <span style={{ fontFamily: 'var(--font-mono)' }}>
          {connector.is_live_collection_active ? 'LIVE ACTIVE' : 'INERT STUB'}
        </span>
      </div>
    </div>
  );
};
