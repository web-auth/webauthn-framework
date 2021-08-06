<?php

declare(strict_types=1);

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

        $this
            ->setLoggerToServiceDefinition($container, AuthenticatorAssertionResponseValidator::class)
            ->setLoggerToServiceDefinition($container, AuthenticatorAttestationResponseValidator::class)
            ->setLoggerToServiceDefinition($container, PublicKeyCredentialLoader::class)
            ->setLoggerToServiceDefinition($container, AttestationObjectLoader::class)
        ;
    }

    private function setLoggerToServiceDefinition(ContainerBuilder $container, string $service): LoggerSetterCompilerPass
    {
        if (!$container->hasDefinition($service)) {
            return $this;
        }

        $definition = $container->getDefinition($service);
        $definition->addMethodCall('setLogger', [new Reference('webauthn.logger')]);

        return $this;
    }
}
