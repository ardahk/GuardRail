/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        ink: '#0B1020',
        mist: '#ECF2FF',
        accent: '#36CFC9',
        warn: '#FF9F45',
        risk: '#FF5D73',
        safe: '#4ADE80'
      },
      boxShadow: {
        panel: '0 10px 30px rgba(8, 15, 35, 0.25)'
      },
      animation: {
        'fade-slide-in': 'fadeSlideIn 0.2s ease-out forwards',
        'window-in': 'windowIn 0.35s ease-out both',
        'breach-pulse': 'breachPulse 2s ease-in-out infinite',
      },
      keyframes: {
        fadeSlideIn: {
          from: { opacity: '0', transform: 'translateY(8px)' },
          to: { opacity: '1', transform: 'translateY(0)' },
        },
        windowIn: {
          from: { opacity: '0', transform: 'scale(0.95) translateY(12px)' },
          to: { opacity: '1', transform: 'scale(1) translateY(0)' },
        },
        breachPulse: {
          '0%, 100%': { boxShadow: '0 0 0 0 rgba(255, 70, 70, 0)' },
          '50%': { boxShadow: '0 0 24px 4px rgba(255, 70, 70, 0.3)' },
        },
      },
    }
  },
  plugins: []
};
