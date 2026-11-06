/** @type {import('tailwindcss').Config} */
export default {
  content: [
    './index.html',
    './src/**/*.{js,ts,jsx,tsx}',
  ],
  theme: {
    extend: {
      colors: {
        obsidian: {
          950: '#050811',
          900: '#070B14',
          850: '#0A0F1D',
          800: '#0D1527',
          750: '#111C34',
          700: '#162342',
        },
        cyber: {
          cyan: '#00F0FF',
          emerald: '#10B981',
          amber: '#F59E0B',
          rose: '#F43F5E',
          purple: '#A855F7',
        },
        slate: {
          50: '#f8fafc',
          100: '#f1f5f9',
          200: '#e2e8f0',
          300: '#cbd5e1',
          400: '#94a3b8',
          500: '#64748b',
          600: '#475569',
          700: '#334155',
          800: '#1e293b',
          900: '#0f172a',
        },
        indigo: {
          50: '#eef2ff',
          100: '#e0e7ff',
          600: '#4f46e5',
          700: '#4338ca',
        },
        emerald: {
          50: '#ecfdf5',
          600: '#059669',
          700: '#047857',
        },
        rose: {
          50: '#fff1f2',
          600: '#e11d48',
        },
        amber: {
          50: '#fffbeb',
          600: '#d97706',
        },
      },
      borderColor: {
        primary: 'var(--color-slate-200)',
        hover: 'var(--color-slate-300)',
        focus: 'var(--color-indigo-600)',
        danger: 'var(--color-rose-600)',
      },
      borderWidth: {
        default: '1px',
      },
    },
  },
  plugins: [],
}

