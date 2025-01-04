<?php

declare(strict_types=1);

namespace Webauthn\Bundle\DependencyInjection\Compiler;

use InvalidArgumentException;
use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Webauthn\Bundle\Routing\Loader;
use function array_key_exists;
use function sprintf;

final class DynamicRouteCompilerPass implements CompilerPassInterface
{
    public const TAG = 'webauthn_controller';

    public function process(ContainerBuilder $container): void
    {
        if (! $container->hasDefinition(Loader::class)) {
            return;
        }

        $definition = $container->getDefinition(Loader::class);

        $taggedServices = $container->findTaggedServiceIds(self::TAG);
        foreach ($taggedServices as $id => $tags) {
            foreach ($tags as $attributes) {
                array_key_exists('path', $attributes) || throw new InvalidArgumentException(sprintf(
                    'The path is missing for "%s"',
                    $id
                ));
                array_key_exists('host', $attributes) || throw new InvalidArgumentException(sprintf(
                    'The host is missing for "%s"',
                    $id
                ));
                $definition->addMethodCall(
                    'add',
                    [$attributes['path'], $attributes['host'], $id, $attributes['method'] ?? 'POST']
                );
            }
        }
    }
}
