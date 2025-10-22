// eslint.config.js
import js from '@eslint/js';
import globals from 'globals';
import { FlatCompat } from '@eslint/eslintrc';
import tsPlugin from '@typescript-eslint/eslint-plugin';
import tsParser from '@typescript-eslint/parser';

const compat = new FlatCompat();

const jestScoped = compat
    .extends('plugin:jest/recommended')
    .map((c) => ({
        ...c,
        files: [
            'src/*/assets/test/**/*.ts',
            '**/__tests__/**/*.{js,ts}',
            '**/test/**/*.{js,ts}'
        ]
    }));

export default [
    js.configs.recommended,

    ...compat.extends(
        'prettier',
        'plugin:@typescript-eslint/eslint-recommended',
        'plugin:@typescript-eslint/recommended'
    ),

    {
        files: ['**/*.{js,ts}'],
        ignores: ['**/node_modules/**', '**/dist/**', '**/build/**', '**/.cache/**'],
        languageOptions: {
            ecmaVersion: 'latest',
            sourceType: 'module',
            parser: tsParser,
            globals: globals.browser
        },
        plugins: {
            '@typescript-eslint': tsPlugin
        },
        rules: {
            '@typescript-eslint/no-explicit-any': 'off',
            '@typescript-eslint/no-empty-function': 'off',
            '@typescript-eslint/ban-ts-comment': 'off',
            '@typescript-eslint/no-unused-vars': [
                'warn',
                {
                    argsIgnorePattern: '^_',
                    caughtErrors: 'all',
                    caughtErrorsIgnorePattern: '^_'
                }
            ],
            quotes: ['error', 'single']
        }
    },

    ...jestScoped
];
