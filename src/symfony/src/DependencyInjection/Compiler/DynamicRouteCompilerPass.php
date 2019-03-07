<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Webauthn\Bundle\DependencyInjection\Compiler;

use Assert\Assertion;
use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Webauthn\Bundle\Routing\Loader;

final class DynamicRouteCompilerPass implements CompilerPassInterface
{
    public const TAG = 'webauthn_transport_binding_profile_controller_request';

    /**
     * {@inheritdoc}
     */
    public function process(ContainerBuilder $container): void
    {
        if (!$container->hasDefinition(Loader::class)) {
            return;
        }

        $definition = $container->getDefinition(Loader::class);

        $taggedServices = $container->findTaggedServiceIds(self::TAG);
        foreach ($taggedServices as $id => $tags) {
            foreach ($tags as $attributes) {
                Assertion::keyExists($attributes, 'path', \Safe\sprintf('The path is missing for "%s"', $id));
                Assertion::keyExists($attributes, 'host', \Safe\sprintf('The host is missing for "%s"', $id));
                $definition->addMethodCall('add', [$attributes['path'], $attributes['host'], $id]);
            }
        }
    }
}
