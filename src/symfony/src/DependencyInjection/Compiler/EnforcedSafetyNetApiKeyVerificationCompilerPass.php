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
use Webauthn\AttestationStatement\AndroidSafetyNetAttestationStatementSupport;

final class EnforcedSafetyNetApiKeyVerificationCompilerPass implements CompilerPassInterface
{
    /**
     * {@inheritdoc}
     */
    public function process(ContainerBuilder $container): void
    {
        if (!$container->hasDefinition(AndroidSafetyNetAttestationStatementSupport::class)
            || !$container->hasAlias('webauthn.android_safetynet.http_client')
            || !$container->hasParameter('webauthn.android_safetynet.api_key')
            || null === $container->getParameter('webauthn.android_safetynet.api_key')
            || !$container->hasAlias('webauthn.android_safetynet.request_factory')
        ) {
            return;
        }

        $definition = $container->getDefinition(AndroidSafetyNetAttestationStatementSupport::class);
        $definition->addMethodCall('enableApiVerification', [
            new Reference('webauthn.android_safetynet.http_client'),
            $container->getParameter('webauthn.android_safetynet.api_key'),
            new Reference('webauthn.android_safetynet.request_factory'),
        ]);
    }
}
