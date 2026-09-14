// Configuration ESLint — **format plat** (`eslint.config.js`).
//
// Pourquoi ce fichier remplace `.eslintrc.cjs` : ESLint 9 puis 10 ne lisent plus le format
// « eslintrc », et l'option `--ext` n'existe plus. La migration n'est donc pas optionnelle dès
// lors qu'ESLint est mis à jour — un bump de version majeur d'ESLint *est* une migration de
// configuration, pas une mise à jour de dépendance.
//
// Volontairement **sans règles type-aware** : le typage strict est déjà garanti par
// `npm run typecheck` (deux `tsc --noEmit`), et les règles type-aware doubleraient le temps de
// lint pour un résultat redondant.

import js from '@eslint/js';
import globals from 'globals';
import reactHooks from 'eslint-plugin-react-hooks';
import reactRefresh from 'eslint-plugin-react-refresh';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  { ignores: ['dist', 'node_modules', 'coverage', '*.cjs'] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    files: ['**/*.{ts,tsx}'],
    languageOptions: {
      ecmaVersion: 'latest',
      sourceType: 'module',
      globals: { ...globals.browser, ...globals.node },
    },
    plugins: {
      'react-hooks': reactHooks,
      'react-refresh': reactRefresh,
    },
    rules: {
      'no-console': ['warn', { allow: ['warn', 'error'] }],
      eqeqeq: ['error', 'always'],
      'no-var': 'error',
      'prefer-const': 'error',
      '@typescript-eslint/no-explicit-any': 'error',
      '@typescript-eslint/no-unused-vars': [
        'error',
        { argsIgnorePattern: '^_', varsIgnorePattern: '^_' },
      ],
      '@typescript-eslint/consistent-type-imports': [
        'error',
        { prefer: 'type-imports', fixStyle: 'inline-type-imports' },
      ],
      ...reactHooks.configs.recommended.rules,
      // Désactivée : plusieurs modules exportent volontairement un provider ou une fabrique ET
      // des hooks (ex. `lib/auth.ts`, `lib/ws.ts`), ce qui est le patron attendu ici ; le HMR
      // reste correct pour les fichiers purement composants.
      'react-refresh/only-export-components': 'off',
    },
  },
  {
    files: ['tests/**/*.ts', '**/*.test.ts'],
    rules: { 'no-console': 'off' },
  },
);
