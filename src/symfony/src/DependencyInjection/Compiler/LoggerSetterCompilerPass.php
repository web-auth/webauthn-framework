<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2020 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Webauthn\Bundle\DependencyInjection\Compiler;

use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Reference;
use Webauthn\Bundle\Service\AuthenticatorAssertionResponseValidator;

final class LoggerSetterCompilerPass implements CompilerPassInterface
{
    /**
     * {@inheritdoc}
     */
    public function process(ContainerBuilder $container): void
    {
        if (!$container->hasAlias('webauthn.logger') || !$container->hasDefinition(AuthenticatorAssertionResponseValidator::class)) {
            return;
        }

        $definition = $container->getDefinition(AuthenticatorAssertionResponseValidator::class);
        $definition->addMethodCall('setLogger', [new Reference('webauthn.logger')]);
    }
}
