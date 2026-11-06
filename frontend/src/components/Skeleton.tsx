export const Skeleton = ({ className, height }: { className?: string; height?: number }) => {
  const size = height || 16;

  const baseClassName = `
    animate-pulse bg-bg-hover rounded
    focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-active focus-visible:ring-offset-2
  `;

  return (
    <div
      className={className ? `${baseClassName} ${className}` : baseClassName}
      style={{ height: `${size}px` }}
    />
  );
};