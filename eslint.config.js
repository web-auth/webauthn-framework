// eslint.config.js
import js from '@eslint/js';
import globals from 'globals';
import { FlatCompat } from '@eslint/eslintrc';

const compat = new FlatCompat();

const jestScoped = compat
    .extends('plugin:jest/recommended')
    .map((c) => ({
        ...c,
        files: [
            'src/*/assets/test/**/*.js',
            '**/__tests__/**/*.js',
            '**/test/**/*.js'
        ]
    }));

export default [
    js.configs.recommended,

    ...compat.extends('prettier'),

    {
        files: ['**/*.js'],
        ignores: ['**/node_modules/**', '**/dist/**', '**/build/**', '**/.cache/**'],
        languageOptions: {
            ecmaVersion: 'latest',
            sourceType: 'module',
            globals: globals.browser
        },
        rules: {
            'no-unused-vars': [
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
