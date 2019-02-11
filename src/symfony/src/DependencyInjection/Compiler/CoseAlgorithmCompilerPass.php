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

use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Reference;

final class CoseAlgorithmCompilerPass implements CompilerPassInterface
{
    public const TAG = 'webauthn_cose_algorithm';

    /**
     * {@inheritdoc}
     */
    public function process(ContainerBuilder $container): void
    {
        if (!$container->hasDefinition('webauthn.cose.algorithm.manager')) {
            return;
        }

        $definition = $container->getDefinition('webauthn.cose.algorithm.manager');

        $taggedServices = $container->findTaggedServiceIds(self::TAG);
        foreach ($taggedServices as $id => $attributes) {
            $definition->addMethodCall('add', [new Reference($id)]);
        }
    }
}
