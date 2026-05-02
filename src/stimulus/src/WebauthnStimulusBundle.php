<?php

declare(strict_types=1);

namespace Webauthn\Stimulus;

use function dirname;
use function is_array;
use function is_string;
use Symfony\Component\AssetMapper\AssetMapperInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\HttpKernel\Bundle\AbstractBundle;

final class WebauthnStimulusBundle extends AbstractBundle
{
    public function prependExtension(ContainerConfigurator $container, ContainerBuilder $builder): void
    {
        if (! $this->isAssetMapperAvailable($builder)) {
            return;
        }

        // Registers assets/src as an AssetMapper path under the @web-auth/webauthn-stimulus
        // namespace so the `path:%PACKAGE%/...` entries published in package.json resolve
        // through ImportMapManager::findAsset(). Without this, importmap:require fails with
        // "The path ... cannot be found" when the recipe processes the package on install
        // (issue #842).
        $builder->prependExtensionConfig('framework', [
            'asset_mapper' => [
                'paths' => [
                    dirname(__DIR__) . '/assets/src' => '@web-auth/webauthn-stimulus',
                ],
            ],
        ]);
    }

    private function isAssetMapperAvailable(ContainerBuilder $container): bool
    {
        if (! interface_exists(AssetMapperInterface::class)) {
            return false;
        }

        $bundlesMetadata = $container->getParameter('kernel.bundles_metadata');
        if (! is_array($bundlesMetadata)) {
            return false;
        }

        $frameworkBundle = $bundlesMetadata['FrameworkBundle'] ?? null;
        if (! is_array($frameworkBundle)) {
            return false;
        }

        $frameworkBundlePath = $frameworkBundle['path'] ?? null;
        if (! is_string($frameworkBundlePath)) {
            return false;
        }

        return is_file($frameworkBundlePath . '/Resources/config/asset_mapper.php');
    }
}
