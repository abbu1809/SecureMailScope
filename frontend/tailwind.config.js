/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        ink: {
          DEFAULT: '#141414',
          soft: '#262626',
        },
        canvas: {
          DEFAULT: '#ffffff',
          soft: '#f3f3f3',
        },
        field: '#f0f0f0',
        hairline: {
          DEFAULT: '#e0e0e0',
          soft: '#f0f0f0',
        },
        accent: {
          DEFAULT: '#0066ff',
          hover: '#0052cc',
        },
        text: {
          muted: '#707070',
          faint: '#adadad',
        },
        // Semantic alert indicators for findings
        risk: {
          critical: '#dc2626',
          high: '#ea580c',
          medium: '#d97706',
          secure: '#16a34a',
        }
      },
      borderRadius: {
        'sm': '16px',
        'md': '24px',
        'full': '9999px',
        'squircle': '30%',
      },
      fontFamily: {
        sans: ['Inter', '-apple-system', 'BlinkMacSystemFont', 'Segoe UI', 'Roboto', 'sans-serif'],
        mono: ['JetBrains Mono', 'Menlo', 'Monaco', 'Courier New', 'monospace'],
      },
      boxShadow: {
        'subtle': '0 1px 3px rgba(0,0,0,0.02)',
      }
    },
  },
  plugins: [],
}
