/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      fontFamily: {
        sans: ["Inter", "system-ui", "sans-serif"],
        mono: ["JetBrains Mono", "ui-monospace", "monospace"],
      },
      colors: {
        ink: {
          950: "#070b14",
          900: "#0b1020",
          850: "#0f1629",
          800: "#141d33",
        },
      },
      boxShadow: {
        glow: "0 0 24px rgba(16, 185, 129, 0.25)",
        "glow-lg": "0 0 48px rgba(16, 185, 129, 0.35)",
        card: "0 8px 32px rgba(0, 0, 0, 0.35)",
      },
      keyframes: {
        aurora: {
          "0%, 100%": { transform: "translate(0, 0) scale(1)" },
          "33%": { transform: "translate(40px, -30px) scale(1.1)" },
          "66%": { transform: "translate(-30px, 25px) scale(0.95)" },
        },
        shimmer: {
          "0%": { backgroundPosition: "-200% 0" },
          "100%": { backgroundPosition: "200% 0" },
        },
      },
      animation: {
        aurora: "aurora 18s ease-in-out infinite",
        "aurora-slow": "aurora 26s ease-in-out infinite reverse",
        shimmer: "shimmer 2.5s linear infinite",
      },
    },
  },
  plugins: [],
};
