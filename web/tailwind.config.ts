import type { Config } from 'tailwindcss'

export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        bg: {
          deep: 'var(--bg-deep)',
          panel: 'var(--bg-panel)',
          'panel-strong': 'var(--bg-panel-strong)',
        },
        border: {
          soft: 'var(--border-soft)',
          active: 'var(--border-active)',
        },
        ink: {
          DEFAULT: 'var(--text-primary)',
          secondary: 'var(--text-secondary)',
        },
        accent: {
          blue: 'var(--accent-blue)',
          purple: 'var(--accent-purple)',
          pink: 'var(--accent-pink)',
        },
        status: {
         success: 'var(--success)',
          warning: 'var(--warning)',
          danger: 'var(--danger)',
          neutral: 'var(--status-neutral)',
        },
      },
      fontFamily: {
        sans: [
          '-apple-system',
          'BlinkMacSystemFont',
          '"SF Pro Text"',
          '"PingFang SC"',
          '"Hiragino Sans GB"',
          '"Noto Sans SC"',
          '"Segoe UI"',
          '"Microsoft YaHei"',
          'sans-serif',
        ],
      },
      borderRadius: {
        glass: '18px',
      },
      backdropBlur: {
        glass: '18px',
      },
      boxShadow: {
        glass: '0 1px 2px rgba(0, 0, 0, 0.04)',
        glow: 'none',
      },
      keyframes: {
        breathe: {
          '0%, 100%': { opacity: '0.55', transform: 'scale(1)' },
          '50%': { opacity: '1', transform: 'scale(1.18)' },
        },
        fadeUp: {
          from: { opacity: '0', transform: 'translateY(8px)' },
          to: { opacity: '1', transform: 'translateY(0)' },
        },
      },
      animation: {
        breathe: 'breathe 2.8s ease-in-out infinite',
        fadeUp: 'fadeUp 0.35s ease-out',
      },
    },
  },
  plugins: [],
} satisfies Config
