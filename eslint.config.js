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
        ],
        // Tests run in Jest under jsdom but still have access to Node globals
        // (e.g. Buffer, used as a base64url helper in payment-controller.test.js).
        languageOptions: {
            ...c.languageOptions,
            globals: {
                ...(c.languageOptions?.globals ?? {}),
                ...globals.node,
                ...globals.jest
            }
        }
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
