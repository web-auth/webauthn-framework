<?php

declare(strict_types=1);

namespace Webauthn\Bundle\DependencyInjection\Compiler;

use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Reference;

final class LoggerSetterCompilerPass implements CompilerPassInterface
{
    public const TAG = 'webauthn_can_log_data';

    public function process(ContainerBuilder $container): void
    {
        if (! $container->hasAlias('webauthn.logger')) {
            return;
        }

        $taggedServices = $container->findTaggedServiceIds(self::TAG);
        foreach ($taggedServices as $id => $attributes) {
            $service = $container->getDefinition($id);
            $service->addMethodCall('setLogger', [new Reference('webauthn.logger')]);
        }
    }
}
