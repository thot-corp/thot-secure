// Tailwind 4 : le greffon PostCSS vit dans `@tailwindcss/postcss` — le paquet
// `tailwindcss` n'en fournit plus, et l'ancien nom échouait à l'import.
export default {
  plugins: {
    '@tailwindcss/postcss': {},
    autoprefixer: {},
  },
};
