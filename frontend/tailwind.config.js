/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,jsx}",
  ],

  theme: {
    extend: {
      colors: {
        vulnix: {
          bg: "#C5C1C1",
          surface: "#F3F4F4",
          primary: "#49A4BB",
          secondary: "#D8A2A2",
          text: "#2C2C2C",
          white: "#FFFFFF",
        },
      },
    },
  },

  plugins: [],
};