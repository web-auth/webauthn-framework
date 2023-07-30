<?php

declare(strict_types=1);

namespace Webauthn\Bundle\DependencyInjection\Compiler;

use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Reference;
use Webauthn\AttestationStatement\AndroidSafetyNetAttestationStatementSupport;

final class EnforcedSafetyNetApiKeyVerificationCompilerPass implements CompilerPassInterface
{
    public function process(ContainerBuilder $container): void
    {
        if (! $container->hasDefinition(AndroidSafetyNetAttestationStatementSupport::class)
            || ! $container->hasAlias('webauthn.android_safetynet.http_client')
            || ! $container->hasParameter('webauthn.android_safetynet.api_key')
            || $container->getParameter('webauthn.android_safetynet.api_key') === null
        ) {
            return;
        }

        $requestFactoryReference = null;
        if ($container->hasAlias('webauthn.android_safetynet.request_factory')) {
            $requestFactoryReference = new Reference('webauthn.android_safetynet.request_factory');
        }

        $definition = $container->getDefinition(AndroidSafetyNetAttestationStatementSupport::class);
        $definition->addMethodCall('enableApiVerification', [
            new Reference('webauthn.android_safetynet.http_client'),
            $container->getParameter('webauthn.android_safetynet.api_key'),
            $requestFactoryReference,
        ]);
    }
}
