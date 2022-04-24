<?php

declare(strict_types=1);

namespace Webauthn\Bundle\DependencyInjection\Compiler;

use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Reference;
use Webauthn\AttestationStatement\AttestationObjectLoader;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\Bundle\Repository\DummyPublicKeyCredentialSourceRepository;
use Webauthn\Bundle\Repository\DummyPublicKeyCredentialUserEntityRepository;
use Webauthn\Bundle\Security\Http\Authenticator\WebauthnAuthenticator;
use Webauthn\Counter\ThrowExceptionIfInvalid;
use Webauthn\PublicKeyCredentialLoader;

final class LoggerSetterCompilerPass implements CompilerPassInterface
{
    /**
     * {@inheritdoc}
     */
    public function process(ContainerBuilder $container): void
    {
        if (! $container->hasAlias('webauthn.logger')) {
            return;
        }

        $this->setLoggerToServiceDefinition($container, AuthenticatorAssertionResponseValidator::class);
        $this->setLoggerToServiceDefinition($container, AuthenticatorAttestationResponseValidator::class);
        $this->setLoggerToServiceDefinition($container, PublicKeyCredentialLoader::class);
        $this->setLoggerToServiceDefinition($container, AttestationObjectLoader::class);
        $this->setLoggerToServiceDefinition($container, ThrowExceptionIfInvalid::class);
        $this->setLoggerToServiceDefinition($container, DummyPublicKeyCredentialUserEntityRepository::class);
        $this->setLoggerToServiceDefinition($container, DummyPublicKeyCredentialSourceRepository::class);
        $this->setLoggerToServiceDefinition($container, WebauthnAuthenticator::class);
    }

    private function setLoggerToServiceDefinition(ContainerBuilder $container, string $service): void
    {
        if (! $container->hasDefinition($service)) {
            return;
        }

        $definition = $container->getDefinition($service);
        $definition->addMethodCall('setLogger', [new Reference('webauthn.logger')]);
    }
}
