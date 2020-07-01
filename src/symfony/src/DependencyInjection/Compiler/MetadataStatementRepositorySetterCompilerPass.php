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
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\MetadataService\MetadataStatementRepository;

final class MetadataStatementRepositorySetterCompilerPass implements CompilerPassInterface
{
    /**
     * {@inheritdoc}
     */
    public function process(ContainerBuilder $container): void
    {
        if (!$container->hasAlias(MetadataStatementRepository::class)) {
            return;
        }

        $this->setLoggerToServiceDefinition($container, AuthenticatorAttestationResponseValidator::class);
    }

    private function setLoggerToServiceDefinition(ContainerBuilder $container, string $service): void
    {
        if (!$container->hasDefinition($service)) {
            return;
        }

        $definition = $container->getDefinition($service);
        $definition->addMethodCall('setMetadataStatementRepository', [new Reference(MetadataStatementRepository::class)]);
    }
}
