interface FilterOption {
  value: string;
  label: string;
  disabled?: boolean;
}

export const Filter = ({
  label,
  options,
  value,
  onChange,
  placeholder = 'Filter...',
  disabled = false,
}: {
  label: string;
  options: FilterOption[];
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
  disabled?: boolean;
}) => {
  return (
    <div className="flex flex-col sm:flex-row gap-2 mb-2">
      <label className="text-xs font-medium text-text-secondary"> {label} </label>

      <select
        value={value || ''}
        onChange={(e) => onChange(e.target.value)}
        disabled={disabled}
        className="
          rounded-sm border border-border-primary border
          text-text-primary
          focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-active focus-visible:ring-offset-2
        "
      >
        <option value="" disabled>
          {placeholder}
        </option>
        {options.map((opt) => (
          <option
            key={opt.value}
            value={opt.value}
            disabled={opt.disabled}
          >
            {opt.label}
          </option>
        ))}
      </select>
    </div>
  );
};