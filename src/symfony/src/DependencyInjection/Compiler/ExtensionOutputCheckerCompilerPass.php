<?php

declare(strict_types=1);

namespace Webauthn\Bundle\DependencyInjection\Compiler;

use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Reference;
use Webauthn\AuthenticationExtensions\ExtensionOutputCheckerHandler;

final class ExtensionOutputCheckerCompilerPass implements CompilerPassInterface
{
    public const TAG = 'webauthn_extension_output_checker';

    public function process(ContainerBuilder $container): void
    {
        if (! $container->hasDefinition(ExtensionOutputCheckerHandler::class)) {
            return;
        }

        $definition = $container->getDefinition(ExtensionOutputCheckerHandler::class);

        $taggedServices = $container->findTaggedServiceIds(self::TAG);
        foreach ($taggedServices as $id => $attributes) {
            $definition->addMethodCall('add', [new Reference($id)]);
        }
    }
}
