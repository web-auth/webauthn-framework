<?php

declare(strict_types=1);

namespace Webauthn\Bundle\DependencyInjection\Compiler;

use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Reference;

final class CoseAlgorithmCompilerPass implements CompilerPassInterface
{
    public const TAG = 'webauthn_cose_algorithm';

    public function process(ContainerBuilder $container): void
    {
        if (! $container->hasDefinition('webauthn.cose.algorithm.manager')) {
            return;
        }

        $definition = $container->getDefinition('webauthn.cose.algorithm.manager');

        $taggedServices = $container->findTaggedServiceIds(self::TAG);
        foreach ($taggedServices as $id => $attributes) {
            $definition->addMethodCall('add', [new Reference($id)]);
        }
    }
}
