<?php

declare(strict_types=1);

use Castor\Attribute\AsOption;
use Castor\Attribute\AsRawTokens;
use Castor\Attribute\AsTask;
use function Castor\context;
use function Castor\guard_min_version;
use function Castor\io;
use function Castor\run;

guard_min_version('v0.23.0');

/**
 * @param array<string> $allowedLicenses
 */
#[AsTask(description: 'Check licenses.')]
function checkLicenses(
    array $allowedLicenses = ['Apache-2.0', 'BSD-2-Clause', 'BSD-3-Clause', 'ISC', 'MIT', 'MPL-2.0', 'OSL-3.0']
): void {
    io()->title('Checking licenses');
    $allowedExceptions = [];
    $command = ['composer', 'licenses', '-f', 'json'];
    $context = context();
    $context->withEnvironment([
        'XDEBUG_MODE' => 'off',
    ]);
    $context->withQuiet();
    $result = run($command, context: $context);
    if (! $result->isSuccessful()) {
        io()->error('Cannot determine licenses');
        exit(1);
    }
    $licenses = json_decode((string) $result->getOutput(), true);
    $disallowed = array_filter(
        $licenses['dependencies'],
        static fn (array $info, $name) => ! in_array($name, $allowedExceptions, true)
            && count(array_diff($info['license'], $allowedLicenses)) === 1,
        \ARRAY_FILTER_USE_BOTH
    );
    $allowed = array_filter(
        $licenses['dependencies'],
        static fn (array $info, $name) => in_array($name, $allowedExceptions, true)
            || count(array_diff($info['license'], $allowedLicenses)) === 0,
        \ARRAY_FILTER_USE_BOTH
    );
    if (count($disallowed) > 0) {
        io()
            ->table(
                ['Package', 'License'],
                array_map(
                    static fn ($name, $info) => [$name, implode(', ', $info['license'])],
                    array_keys($disallowed),
                    $disallowed
                )
            );
        io()
            ->error('Disallowed licenses found');
        exit(1);
    }
    io()
        ->table(
            ['Package', 'License'],
            array_map(
                static fn ($name, $info) => [$name, implode(', ', $info['license'])],
                array_keys($allowed),
                $allowed
            )
        );
    io()
        ->success('All licenses are allowed');
}

#[AsTask(description: 'Runs a Symfony Console command from the Docket Container.', ignoreValidationErrors: true)]
function console(#[AsRawTokens] array $args = []): void
{
    php(['bin/console', ...$args]);
}

#[AsTask(description: 'Runs a PHP command from the Docket Container.', ignoreValidationErrors: true)]
function php(#[AsRawTokens] array $args = []): void
{
    $inContainer = file_exists('/.dockerenv');
    $hasDocker = trim(shell_exec('command -v docker') ?? '') !== '';

    if (! $hasDocker || $inContainer) {
        run($args);
        return;
    }

    run(['php', ...$args]);
}

function phpqa(array $command, array $dockerOptions = []): void
{
    $inContainer = file_exists('/.dockerenv');
    $hasDocker = trim(shell_exec('command -v docker') ?? '') !== '';
    $phpVersion = getenv('PHP_VERSION') ?: \PHP_MAJOR_VERSION . '.' . \PHP_MINOR_VERSION;

    if (! $hasDocker || $inContainer) {
        run($command);
        return;
    }

    $defaultDockerOptions = [
        '--rm',
        '--init',
        '-it',
        '--user', sprintf('%s:%s', getmyuid(), getmygid()),
        '--pull', 'always',
        '-v', getcwd() . ':/project',
        '-v', getcwd() . '/tmp-phpqa:/project/tmp-phpqa',
        '-w', '/project',
        '-e', 'XDEBUG_MODE=off',
        '-e', 'PHP_INI_SCAN_DIR=/usr/local/etc/php/conf.d',
        '-e', 'PHP_INI_ENTRY=sys_temp_dir=/project/tmp-phpqa',
    ];

    run([
        'docker', 'run',
        ...$defaultDockerOptions,
        ...$dockerOptions,
        sprintf('ghcr.io/spomky-labs/phpqa:%s', $phpVersion),
        ...$command,
    ]);
}

#[AsTask(description: 'Update the PHPQA Docker image')]
function phpqa_update(): void
{
    $phpVersion = getenv('PHP_VERSION') ?: (\PHP_MAJOR_VERSION . '.' . \PHP_MINOR_VERSION);

    run(['docker', 'pull', 'ghcr.io/spomky-labs/phpqa:' . $phpVersion]);
}

#[AsTask(description: 'Run PHPUnit tests with coverage', ignoreValidationErrors: true)]
function phpunit(#[AsRawTokens] array $args = []): void
{
    phpqa(
        [
            'composer', 'exec', '--', 'phpunit-11',
            '--coverage-xml', '.ci-tools/coverage',
            '--log-junit=.ci-tools/coverage/junit.xml',
            '--configuration', '.ci-tools/phpunit.xml.dist',
            '--display-warnings',
            '--display-deprecations',
            ...$args,
        ],
        ['-e', 'XDEBUG_MODE=coverage']
    );
}

#[AsTask(description: 'Run Easy Coding Standard')]
function ecs(): void
{
    phpqa(['composer', 'exec', '--', 'ecs', 'check', '--config', '.ci-tools/ecs.php']);
}

#[AsTask(description: 'Fix coding style with Easy Coding Standard')]
function ecs_fix(): void
{
    phpqa(['composer', 'exec', '--', 'ecs', 'check', '--config', '.ci-tools/ecs.php', '--fix']);
}

#[AsTask(description: 'Run Rector dry-run')]
function rector(): void
{
    phpqa(['composer', 'exec', '--', 'rector', 'process', '--dry-run', '--config', '.ci-tools/rector.php']);
}

#[AsTask(description: 'Run Rector with fix')]
function rector_fix(): void
{
    phpqa(['composer', 'exec', '--', 'rector', 'process', '--config', '.ci-tools/rector.php']);
}

#[AsTask(description: 'Run PHPStan')]
function phpstan(): void
{
    phpqa(
        [
            'composer', 'exec', '--', 'phpstan', 'analyse', '--error-format=github', '--configuration=.ci-tools/phpstan.neon']
    );
}

#[AsTask(description: 'Generate PHPStan baseline')]
function phpstan_baseline(): void
{
    phpqa([
        'composer', 'exec', '--', 'phpstan', 'analyse',
        '--configuration=.ci-tools/phpstan.neon',
        '--generate-baseline=.ci-tools/phpstan-baseline.neon',
    ]);
}

#[AsTask(description: 'Run Deptrac')]
function deptrac(): void
{
    phpqa([
        'composer', 'exec', '--', 'deptrac',
        '--config-file', '.ci-tools/deptrac.yaml',
        '--report-uncovered',
        '--report-skipped',
        '--fail-on-uncovered',
    ]);
}

#[AsTask(description: 'Run PHP parallel linter')]
function lint(): void
{
    phpqa(['composer', 'exec', '--', 'parallel-lint', 'src', 'tests']);
}

/**
 * Infection never runs the test suite itself. It reads the XML coverage and the JUnit report that "castor phpunit"
 * writes to .ci-tools/coverage, and runs each mutant against the test cases covering its line with the phpunit-11
 * binary of the phpqa image (see infection.json.dist), not with the PHPUnit 13 that Composer resolves in vendor/bin.
 *
 * With --diff, only the lines added or modified since the merge base with --base are mutated. Infection runs
 * "git diff" on the source directories of infection.json.dist as they are written, which is why that file sits at
 * the root of the repository and not in .ci-tools. A diff that touches no source file is a success.
 */
#[AsTask(description: 'Run Infection for mutation testing')]
function infect(
    int $minMsi = 0,
    int $minCoveredMsi = 0,
    #[AsOption(description: 'Mutate only the lines added or modified since --base, committed or not')]
    bool $diff = false,
    #[AsOption(
        description: 'The branch or commit the diff of --diff is taken from; Infection narrows it to the merge base with HEAD'
    )]
    string $base = 'origin/HEAD',
    #[AsOption(
        description: 'Reuse the coverage of the last "castor phpunit" in .ci-tools/coverage instead of running the tests again'
    )]
    bool $reuseCoverage = false,
): void {
    if (! $reuseCoverage) {
        phpunit();
    } elseif (! is_file('.ci-tools/coverage/index.xml') || ! is_file('.ci-tools/coverage/junit.xml')) {
        io()->error('No coverage to reuse in .ci-tools/coverage: run "castor phpunit" first, or drop --reuse-coverage.');
        exit(1);
    }

    $options = [
        '--coverage=.ci-tools/coverage',
        '--skip-initial-tests',
        sprintf('--min-msi=%d', $minMsi),
        sprintf('--min-covered-msi=%d', $minCoveredMsi),
        '--threads=max',
        '--logger-github',
        '-s',
        '--only-covering-test-cases',
    ];
    if ($diff) {
        $options[] = '--git-diff-lines';
        $options[] = '--git-diff-base=' . $base;
    }

    phpqa(['composer', 'exec', '--', 'infection', ...$options]);
}

#[AsTask(description: 'Run JS tests')]
function js(): void
{
    io()->title('Running JS tests');
    run(['npm', 'install', '--force']);
    run(['npm', 'test']);
}

#[AsTask(description: 'Fix code style and apply Rector rules, then run static analysis.')]
function prepare_pr(): void
{
    io()->title('Preparing code for pull request…');

    ecs_fix();
    rector_fix();

    io()
        ->section('Running static analysis…');
    phpstan_baseline();
    deptrac();
    lint();

    io()
        ->success('Code is ready. You may now commit and push your changes.');
}
