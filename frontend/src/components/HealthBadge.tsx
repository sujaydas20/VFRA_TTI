interface HealthBadgeProps {
  status: 'healthy' | 'degraded' | 'unavailable' | 'disabled' | 'unconfigured' | 'disconnected';
}

export const HealthBadge: React.FC<HealthBadgeProps> = ({ status }) => {
  switch (status) {
    case 'healthy':
      return <span className="badge badge-emerald">Online</span>;
    case 'degraded':
      return <span className="badge badge-amber">Degraded</span>;
    case 'disabled':
      return <span className="badge badge-purple">Inert / Safe</span>;
    case 'unavailable':
    case 'disconnected':
      return <span className="badge badge-rose">Offline</span>;
    default:
      return <span className="badge badge-amber">{status}</span>;
  }
};