<?php

declare(strict_types=1);

namespace Webauthn\Bundle\DependencyInjection\Compiler;

use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Reference;

final class EventDispatcherSetterCompilerPass implements CompilerPassInterface
{
    public const TAG = 'webauthn_can_dispatch_events';

    public function process(ContainerBuilder $container): void
    {
        if (! $container->hasAlias('webauthn.event_dispatcher')) {
            return;
        }

        $taggedServices = $container->findTaggedServiceIds(self::TAG);
        foreach ($taggedServices as $id => $attributes) {
            $service = $container->getDefinition($id);
            $service->addMethodCall('setEventDispatcher', [new Reference('webauthn.event_dispatcher')]);
        }
    }
}
