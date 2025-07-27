import js from '@eslint/js';
import tseslint from 'typescript-eslint';

export default tseslint.config(
    { ignores: ['dist/**', 'node_modules/**', 'eslint.config.*'] },

    js.configs.recommended,

    {
        files: ['**/*.ts', '**/*.tsx'],
        extends: [
            tseslint.configs.recommendedTypeChecked,
            tseslint.configs.stylisticTypeChecked
        ],
        languageOptions: {
            parserOptions: {
                projectService: true,
                tsconfigRootDir: import.meta.dirname,
            },
        },
        rules: {
            '@typescript-eslint/consistent-type-imports': 'error',
            '@typescript-eslint/no-floating-promises': 'error',
        },
    },

    {
        files: ['**/*.js', '**/*.mjs', '**/*.cjs'],
        extends: [tseslint.configs.disableTypeChecked],
    },
);
