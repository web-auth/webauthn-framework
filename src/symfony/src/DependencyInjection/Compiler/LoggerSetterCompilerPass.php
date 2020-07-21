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
use Webauthn\AttestationStatement\AttestationObjectLoader;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\PublicKeyCredentialLoader;

final class LoggerSetterCompilerPass implements CompilerPassInterface
{
    /**
     * {@inheritdoc}
     */
    public function process(ContainerBuilder $container): void
    {
        if (!$container->hasAlias('webauthn.logger')) {
            return;
        }

        $this->setLoggerToServiceDefinition($container, AuthenticatorAssertionResponseValidator::class);
        $this->setLoggerToServiceDefinition($container, AuthenticatorAttestationResponseValidator::class);
        $this->setLoggerToServiceDefinition($container, PublicKeyCredentialLoader::class);
        $this->setLoggerToServiceDefinition($container, AttestationObjectLoader::class);
    }

    private function setLoggerToServiceDefinition(ContainerBuilder $container, string $service): void
    {
        if (!$container->hasDefinition($service)) {
            return;
        }

        $definition = $container->getDefinition($service);
        $definition->addMethodCall('setLogger', [new Reference('webauthn.logger')]);
    }
}
