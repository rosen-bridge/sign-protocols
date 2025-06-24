export default {
  '*.{ts,go}': () => 'npm run type-check --workspaces',
  '*.go': () => 'npm run lint --workspace services/tss-api',
  '*.{js,ts}': 'eslint --fix',
  '*': 'prettier --ignore-unknown --write',
};
