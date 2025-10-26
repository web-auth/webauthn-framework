const resolve = require('@rollup/plugin-node-resolve');
const commonjs = require('@rollup/plugin-commonjs');
const fs = require('fs');
const glob = require('glob');
const path = require('path');

/**
 * Guarantees that any files imported from a peer dependency are treated as an external.
 *
 * For example, if we import `chart.js/auto`, that would not normally
 * match the "chart.js" we pass to the "externals" config. This plugin
 * catches that case and adds it as an external.
 *
 * Inspired by https://github.com/oat-sa/rollup-plugin-wildcard-external
 */
const wildcardExternalsPlugin = (peerDependencies) => ({
    name: 'wildcard-externals',
    resolveId(source, importer) {
        if (importer) {
            let matchesExternal = false;
            peerDependencies.forEach((peerDependency) => {
                if (source.includes(`/${peerDependency}/`)) {
                    matchesExternal = true;
                }
            });

            if (matchesExternal) {
                return {
                    id: source,
                    external: true,
                    moduleSideEffects: true
                };
            }
        }

        return null; // other ids should be handled as usually
    }
});


const file = process.env.INPUT_FILE;
const packageRoot = path.join(file, '..', '..');
const packagePath = path.join(packageRoot, 'package.json');
const packageData = JSON.parse(fs.readFileSync(packagePath, 'utf8'));
const peerDependencies = [
    '@hotwired/stimulus',
    ...(packageData.peerDependencies ? Object.keys(packageData.peerDependencies) : [])
];

module.exports = {
    input: file,
    output: {
        file: path.join(packageRoot, 'dist', path.basename(file, '.js') + '.js'),
        format: 'esm',
    },
    external: peerDependencies,
    plugins: [
        resolve(),
        commonjs(),
        wildcardExternalsPlugin(peerDependencies),
    ],
};
