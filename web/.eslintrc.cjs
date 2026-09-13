/* eslint-env node */
/**
 * Configuration ESLint (format « eslintrc ») — volontairement sans règles
 * type-aware : le typage strict est déjà garanti par `npm run typecheck`.
 */
module.exports = {
  root: true,
  env: { browser: true, es2022: true, node: true },
  parser: '@typescript-eslint/parser',
  parserOptions: { ecmaVersion: 'latest', sourceType: 'module' },
  plugins: ['@typescript-eslint', 'react-hooks', 'react-refresh'],
  extends: ['eslint:recommended', 'plugin:@typescript-eslint/recommended'],
  ignorePatterns: ['dist', 'node_modules', 'coverage', '*.cjs'],
  settings: { react: { version: 'detect' } },
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
    'react-hooks/rules-of-hooks': 'error',
    'react-hooks/exhaustive-deps': 'warn',
    // Désactivée : plusieurs modules exportent volontairement un provider/une
    // fabrique ET des hooks (ex. `lib/auth.ts`, `lib/ws.ts`), ce qui est le
    // patron attendu ici ; le HMR reste correct pour les fichiers purement
    // composants.
    'react-refresh/only-export-components': 'off',
  },
  overrides: [
    {
      files: ['tests/**/*.ts', '**/*.test.ts'],
      env: { node: true },
      rules: { 'no-console': 'off' },
    },
  ],
};
