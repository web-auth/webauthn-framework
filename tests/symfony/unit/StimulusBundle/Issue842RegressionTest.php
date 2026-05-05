<?php

declare(strict_types=1);

namespace Webauthn\Tests\Bundle\Unit\StimulusBundle;

use const JSON_THROW_ON_ERROR;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Bundle\FrameworkBundle\FrameworkBundle;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Webauthn\Stimulus\WebauthnStimulusBundle;

/**
 * Issue #842: upgrading from 5.2.x to 5.3.0 broke `importmap:require` because the bundle no longer
 * registered its assets directory as an AssetMapper path, leaving the new `path:%PACKAGE%/...`
 * importmap entries unresolvable. The bundle must prepend the `framework.asset_mapper.paths` config
 * whenever AssetMapper is available, and the canonical `@web-auth/webauthn-stimulus` import name
 * must be present alongside the legacy `webauthn` subpath.
 *
 * @internal
 */
final class Issue842RegressionTest extends TestCase
{
    #[Test]
    public function bundleRegistersAssetMapperPathWhenAssetMapperIsAvailable(): void
    {
        $builder = $this->buildContainerWithFrameworkBundle();
        $configurator = static::createStub(ContainerConfigurator::class);

        $bundle = new WebauthnStimulusBundle();
        $bundle->prependExtension($configurator, $builder);

        $configs = $builder->getExtensionConfig('framework');
        static::assertNotSame([], $configs, 'Bundle must prepend a framework config when AssetMapper is installed.');

        $assetMapperPaths = $configs[0]['asset_mapper']['paths'] ?? null;
        static::assertIsArray($assetMapperPaths, 'asset_mapper.paths must be prepended.');

        $expectedDir = realpath(__DIR__ . '/../../../../src/stimulus/assets/src');
        static::assertNotFalse($expectedDir, 'assets/src directory must exist in the source tree.');

        $resolved = [];
        foreach ($assetMapperPaths as $dir => $namespace) {
            $resolved[realpath($dir) ?: $dir] = $namespace;
        }
        static::assertSame(
            '@web-auth/webauthn-stimulus',
            $resolved[$expectedDir] ?? null,
            'assets/src must be exposed under the @web-auth/webauthn-stimulus namespace.',
        );
    }

    #[Test]
    public function bundleSkipsPrependWhenFrameworkBundleIsMissing(): void
    {
        $builder = new ContainerBuilder();
        $builder->setParameter('kernel.bundles_metadata', []);
        $configurator = static::createStub(ContainerConfigurator::class);

        $bundle = new WebauthnStimulusBundle();
        $bundle->prependExtension($configurator, $builder);

        static::assertSame([], $builder->getExtensionConfig('framework'));
    }

    #[Test]
    public function packageJsonExposesCanonicalImportName(): void
    {
        $packageJson = $this->readPackageJson();
        $importmap = $packageJson['symfony']['importmap'] ?? [];

        static::assertArrayHasKey(
            '@web-auth/webauthn-stimulus',
            $importmap,
            'package.json must expose the canonical @web-auth/webauthn-stimulus import name.',
        );
        static::assertSame(
            'path:%PACKAGE%/src/index.js',
            $importmap['@web-auth/webauthn-stimulus'],
            'Canonical entry must point to src/index.js so the package can be imported as a whole.',
        );
    }

    #[Test]
    public function packageJsonKeepsLegacyWebauthnSubpathForBackwardCompatibility(): void
    {
        $packageJson = $this->readPackageJson();
        $importmap = $packageJson['symfony']['importmap'] ?? [];

        static::assertArrayHasKey(
            '@web-auth/webauthn-stimulus/webauthn',
            $importmap,
            'Legacy /webauthn subpath must still be exposed for projects upgrading from 5.2.x.',
        );
        static::assertSame(
            'path:%PACKAGE%/src/controller.js',
            $importmap['@web-auth/webauthn-stimulus/webauthn'],
            'Legacy subpath must keep pointing at the combined controller.js file.',
        );
    }

    private function buildContainerWithFrameworkBundle(): ContainerBuilder
    {
        $frameworkBundle = realpath(__DIR__ . '/../../../../vendor/symfony/framework-bundle');
        static::assertNotFalse(
            $frameworkBundle,
            'symfony/framework-bundle must be installed for this regression test (composer install).',
        );

        $builder = new ContainerBuilder();
        $builder->setParameter('kernel.bundles_metadata', [
            'FrameworkBundle' => [
                'path' => $frameworkBundle,
                'namespace' => 'Symfony\\Bundle\\FrameworkBundle',
                'class' => FrameworkBundle::class,
            ],
        ]);

        return $builder;
    }

    /**
     * @return array<string, mixed>
     */
    private function readPackageJson(): array
    {
        $path = __DIR__ . '/../../../../src/stimulus/assets/package.json';
        static::assertFileExists($path);

        $decoded = json_decode((string) file_get_contents($path), true, flags: JSON_THROW_ON_ERROR);
        static::assertIsArray($decoded);

        return $decoded;
    }
}
