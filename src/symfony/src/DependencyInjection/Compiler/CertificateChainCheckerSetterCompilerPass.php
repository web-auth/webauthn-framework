<?php

declare(strict_types=1);

namespace Webauthn\Bundle\DependencyInjection\Compiler;

use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Reference;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\CertificateChainChecker\CertificateChainChecker;

final class CertificateChainCheckerSetterCompilerPass implements CompilerPassInterface
{
    /**
     * {@inheritdoc}
     */
    public function process(ContainerBuilder $container): void
    {
        if (!$container->hasDefinition(CertificateChainChecker::class) || !$container->hasDefinition(AuthenticatorAttestationResponseValidator::class)) {
            return;
        }

        $definition = $container->getDefinition(AuthenticatorAttestationResponseValidator::class);
        $definition->addMethodCall('setCertificateChainChecker', [new Reference(CertificateChainChecker::class)]);
    }
}
