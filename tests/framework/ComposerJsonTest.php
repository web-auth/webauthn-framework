<?php

declare(strict_types=1);

namespace Webauthn\Tests;

use DirectoryIterator;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Traversable;
use function sprintf;
use const JSON_THROW_ON_ERROR;

/**
 * @internal
 */
final class ComposerJsonTest extends TestCase
{
    private const SRC_DIR = __DIR__ . '/../../src';

    #[Test]
    public function packageDependenciesEqualRootDependencies(): void
    {
        $usedDependencies = ['symfony/symfony']; // Some builds add this to composer.json
        $rootDependencies = $this->getComposerDependencies(__DIR__ . '/../../composer.json');

        foreach ($this->listSubPackages() as $package) {
            $packageDependencies = $this->getComposerDependencies(self::SRC_DIR . '/' . $package . '/composer.json');
            foreach ($packageDependencies as $dependency => $version) {
                // Skip web-auth/* dependencies, except cose-lib
                if ($dependency !== 'web-auth/cose-lib' && str_starts_with($dependency, 'web-auth/')) {
                    continue;
                }

                $message = sprintf(
                    'Dependency "%s" from package "%s" is not defined in root composer.json',
                    $dependency,
                    $package
                );
                static::assertArrayHasKey($dependency, $rootDependencies, $message);

                $message = sprintf(
                    'Dependency "%s:%s" from package "%s" requires a different version in the root composer.json',
                    $dependency,
                    $version,
                    $package
                );
                static::assertSame($version, $rootDependencies[$dependency], $message);

                $usedDependencies[] = $dependency;
            }
        }

        $unusedDependencies = array_diff(array_keys($rootDependencies), array_unique($usedDependencies));
        $message = sprintf(
            'Dependencies declared in root composer.json, which are not declared in any sub-package: %s',
            implode('', $unusedDependencies)
        );
        static::assertCount(0, $unusedDependencies, $message);
    }

    #[Test]
    public function rootReplacesSubPackages(): void
    {
        $rootReplaces = $this->getComposerReplaces(__DIR__ . '/../../composer.json');
        foreach ($this->listSubPackages() as $package) {
            $packageName = $this->getComposerPackageName(self::SRC_DIR . '/' . $package . '/composer.json');
            $message = sprintf('Root composer.json must replace the sub-packages "%s"', $packageName);
            static::assertArrayHasKey($packageName, $rootReplaces, $message);
        }
    }

    private function listSubPackages(): Traversable
    {
        foreach (new DirectoryIterator(self::SRC_DIR) as $dirInfo) {
            if ($dirInfo->isDir() && ! $dirInfo->isDot()) {
                yield $dirInfo->getFilename();
            }
        }
    }

    private function getComposerDependencies(string $composerFilePath): array
    {
        return $this->parseComposerFile($composerFilePath)['require'] ?? [];
    }

    private function getComposerPackageName(string $composerFilePath): string
    {
        return $this->parseComposerFile($composerFilePath)['name'];
    }

    private function getComposerReplaces(string $composerFilePath): array
    {
        return $this->parseComposerFile($composerFilePath)['replace'];
    }

    private function parseComposerFile(string $composerFilePath): array
    {
        return json_decode(file_get_contents($composerFilePath), true, 512, JSON_THROW_ON_ERROR);
    }
}
