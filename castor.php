<?php

declare(strict_types=1);

use Castor\Attribute\AsOption;
use Castor\Attribute\AsTask;
use function Castor\context;
use function Castor\io;
use function Castor\run;

#[AsTask(description: 'Run mutation testing')]
function infect(int $minMsi = 0, int $minCoveredMsi = 0, bool $ci = false): void
{
    io()->title('Running infection');
    $nproc = run('nproc');
    if (! $nproc->isSuccessful()) {
        io()->error('Cannot determine the number of processors');
        return;
    }
    $threads = (int) $nproc->getOutput();
    $command = [
        'php',
        'vendor/bin/infection',
        sprintf('--min-msi=%s', $minMsi),
        sprintf('--min-covered-msi=%s', $minCoveredMsi),
        sprintf('--threads=%s', $threads),
    ];
    if ($ci) {
        $command[] = '--logger-github';
        $command[] = '-s';
    }

    $context = context()
        ->withEnvironment([
            'XDEBUG_MODE' => 'coverage',
        ])
    ;
    run($command, context: $context);
}

#[AsTask(description: 'Run tests')]
function test(bool $coverageHtml = false, bool $coverageText = false, null|string $group = null): void
{
    io()->title('Running tests');
    $command = ['php', 'vendor/bin/phpunit', '--color'];

    $context = context()
        ->withEnvironment([
            'XDEBUG_MODE' => 'off',
        ])
    ;
    if ($coverageHtml) {
        $command[] = '--coverage-html=build/coverage';
        $context = $context->withEnvironment([
            'XDEBUG_MODE' => 'coverage',
        ]);
    }
    if ($coverageText) {
        $command[] = '--coverage-text';
        $context = $context->withEnvironment([
            'XDEBUG_MODE' => 'coverage',
        ]);
    }
    if ($group !== null) {
        $command[] = sprintf('--group=%s', $group);
    }
    run($command, context: $context);
}

#[AsTask(description: 'Coding standards check')]
function cs(
    #[AsOption(description: 'Fix issues if possible')]
    bool $fix = false,
    #[AsOption(description: 'Clear cache')]
    bool $clearCache = false
): void {
    io()->title('Running coding standards check');
    $command = ['php', 'vendor/bin/ecs', 'check'];
    $context = context()
        ->withEnvironment([
            'XDEBUG_MODE' => 'off',
        ])
    ;
    if ($fix) {
        $command[] = '--fix';
    }
    if ($clearCache) {
        $command[] = '--clear-cache';
    }
    run($command, context: $context);
}

#[AsTask(description: 'Running PHPStan')]
function stan(bool $baseline = false): void
{
    io()->title('Running PHPStan');
    $command = ['php', 'vendor/bin/phpstan', 'analyse'];
    if ($baseline) {
        $command[] = '--generate-baseline';
    }
    $context = context()
        ->withEnvironment([
            'XDEBUG_MODE' => 'off',
        ])
    ;
    run($command, context: $context);
}

#[AsTask(description: 'Validate Composer configuration')]
function validate(): void
{
    io()->title('Validating Composer configuration');
    $command = ['composer', 'validate', '--strict'];
    $context = context()
        ->withEnvironment([
            'XDEBUG_MODE' => 'off',
        ])
    ;
    run($command, context: $context);

    $command = ['composer', 'dump-autoload', '--optimize', '--strict-psr'];
    run($command, context: $context);
}

/**
 * @param array<string> $allowedLicenses
 */
#[AsTask(description: 'Check licenses')]
function checkLicenses(
    array $allowedLicenses = ['Apache-2.0', 'BSD-2-Clause', 'BSD-3-Clause', 'ISC', 'MIT', 'MPL-2.0', 'OSL-3.0']
): void {
    io()->title('Checking licenses');
    $allowedExceptions = [];
    $command = ['composer', 'licenses', '-f', 'json'];
    $context = context()
        ->withEnvironment([
            'XDEBUG_MODE' => 'off',
        ])
    ;
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

#[AsTask(description: 'Run Rector')]
function rector(
    #[AsOption(description: 'Fix issues if possible')]
    bool $fix = false,
    #[AsOption(description: 'Clear cache')]
    bool $clearCache = false
): void {
    io()->title('Running Rector');
    $command = ['php', 'vendor/bin/rector', 'process', '--ansi'];
    if (! $fix) {
        $command[] = '--dry-run';
    }
    if ($clearCache) {
        $command[] = '--clear-cache';
    }
    $context = context()
        ->withEnvironment([
            'XDEBUG_MODE' => 'off',
        ])
    ;
    run($command, context: $context);
}

#[AsTask(description: 'Run Rector')]
function deptrac(): void
{
    io()->title('Running Rector');
    $command = ['php', 'vendor/bin/deptrac', 'analyse', '--fail-on-uncovered', '--no-cache'];
    $context = context()
        ->withEnvironment([
            'XDEBUG_MODE' => 'off',
        ])
    ;
    run($command, context: $context);
}

#[AsTask(description: 'Run Linter')]
function lint(): void
{
    io()->title('Running Linter');
    $command = ['composer', 'exec', '--', 'parallel-lint', __DIR__ . '/src/', __DIR__ . '/tests/'];
    $context = context()
        ->withEnvironment([
            'XDEBUG_MODE' => 'off',
        ])
    ;
    run($command, context: $context);
}

#[AsTask(description: 'Run JS tests')]
function js(): void
{
    io()->title('Running JS tests');
    run(['npm', 'install', '--force']);
    run(['npm', 'test']);
}
