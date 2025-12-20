const path = require('path');

module.exports = {
    testEnvironmentOptions: {
        "url": "https://localhost/"
    },
    verbose: true,
    testRegex: "test/.*\\.test.js",
    testEnvironment: 'jsdom',
    setupFilesAfterEnv: [
        path.join(__dirname, 'tests/setup.js'),
    ],
    transform: {
        '\\.js$': ['babel-jest', { configFile: path.join(__dirname, './babel.config.cjs') }]
    },
    "transformIgnorePatterns": [
        "node_modules/(?!@ngrx|(?!deck.gl)|ng-dynamic)"
    ]
};
