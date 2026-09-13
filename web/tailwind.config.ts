import type { Config } from 'tailwindcss';

/**
 * Thème « SOC » : fond slate-950, panneaux slate-900/800, accents cyan (nominal),
 * amber (avertissement / dry-run) et rose (critique / destructif). Police système.
 */
const config: Config = {
  darkMode: 'class',
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        soc: {
          bg: '#020617',
          panel: '#0b1220',
          raised: '#111c2e',
          border: '#1e293b',
          'border-strong': '#334155',
          muted: '#94a3b8',
          accent: '#22d3ee',
          warn: '#f59e0b',
          danger: '#f43f5e',
          ok: '#34d399',
        },
      },
      fontFamily: {
        sans: [
          'system-ui',
          '-apple-system',
          'Segoe UI',
          'Roboto',
          'Helvetica Neue',
          'Arial',
          'Noto Sans',
          'sans-serif',
          'Apple Color Emoji',
          'Segoe UI Emoji',
        ],
        mono: [
          'ui-monospace',
          'SFMono-Regular',
          'Cascadia Mono',
          'Consolas',
          'Liberation Mono',
          'monospace',
        ],
      },
      fontSize: {
        '2xs': ['0.6875rem', { lineHeight: '1rem' }],
      },
      boxShadow: {
        panel: '0 1px 0 0 rgba(148, 163, 184, 0.06), 0 12px 32px -18px rgba(0, 0, 0, 0.9)',
      },
      keyframes: {
        'pulse-ring': {
          '0%': { opacity: '0.9', transform: 'scale(0.9)' },
          '70%': { opacity: '0', transform: 'scale(1.6)' },
          '100%': { opacity: '0', transform: 'scale(1.6)' },
        },
        'fade-in': {
          from: { opacity: '0', transform: 'translateY(4px)' },
          to: { opacity: '1', transform: 'translateY(0)' },
        },
      },
      animation: {
        'pulse-ring': 'pulse-ring 1.8s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'fade-in': 'fade-in 120ms ease-out',
      },
    },
  },
  plugins: [],
};

export default config;
