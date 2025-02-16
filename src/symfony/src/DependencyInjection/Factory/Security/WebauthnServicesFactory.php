<?php

declare(strict_types=1);

namespace Webauthn\Bundle\DependencyInjection\Factory\Security;

use Symfony\Component\DependencyInjection\ChildDefinition;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Reference;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\Bundle\DependencyInjection\Compiler\EventDispatcherSetterCompilerPass;
use Webauthn\CeremonyStep\CeremonyStepManager;
use Webauthn\CeremonyStep\CeremonyStepManagerFactory;

/**
 * @internal Helper class for WebauthnFactory only
 */
class WebauthnServicesFactory
{
    /**
     * @param array<string,mixed> $config
     */
    public function createWebauthnFirewallConfig(
        ContainerBuilder $container,
        string $firewallName,
        array $config
    ): string {
        $firewallConfigId = WebauthnFactory::FIREWALL_CONFIG_ID_PREFIX . $firewallName;
        $container
            ->setDefinition($firewallConfigId, new ChildDefinition(WebauthnFactory::FIREWALL_CONFIG_DEFINITION_ID))
            ->replaceArgument(0, $config)
            ->replaceArgument(1, $firewallName);

        return $firewallConfigId;
    }

    /**
     * @param string[] $securedRpIds
     */
    public function createAuthenticatorAssertionResponseValidator(
        ContainerBuilder $container,
        string $firewallName,
        // @deprecated Will be removed in 6.0.0
        array $securedRpIds
    ): string {
        $ceremonyStepManagerId = WebauthnFactory::CEREMONY_STEP_MANAGER_ID_PREFIX . 'request.' . $firewallName;
        $container
            ->setDefinition($ceremonyStepManagerId, new Definition(CeremonyStepManager::class))
            ->setFactory([new Reference(CeremonyStepManagerFactory::class), 'requestCeremony'])
            ->setArguments([$securedRpIds])
        ;

        $authenticatorAssertionResponseValidatorId = WebauthnFactory::AUTHENTICATOR_ASSERTION_RESPONSE_VALIDATOR_ID_PREFIX . $firewallName;
        $container
            ->setDefinition(
                $authenticatorAssertionResponseValidatorId,
                new Definition(AuthenticatorAssertionResponseValidator::class)
            )
            ->setArguments([new Reference($ceremonyStepManagerId)])
            ->addTag(EventDispatcherSetterCompilerPass::TAG)
        ;

        return $authenticatorAssertionResponseValidatorId;
    }

    /**
     * @param string[] $securedRpIds
     */
    public function createAuthenticatorAttestationResponseValidator(
        ContainerBuilder $container,
        string $firewallName,
        // @deprecated Will be removed in 6.0.0
        array $securedRpIds
    ): string {
        $ceremonyStepManagerId = WebauthnFactory::CEREMONY_STEP_MANAGER_ID_PREFIX . 'creation.' . $firewallName;
        $container
            ->setDefinition($ceremonyStepManagerId, new Definition(CeremonyStepManager::class))
            ->setFactory([new Reference(CeremonyStepManagerFactory::class), 'creationCeremony'])
            ->setArguments([$securedRpIds])
        ;

        $authenticatorAttestationResponseValidatorId = WebauthnFactory::AUTHENTICATOR_ATTESTATION_RESPONSE_VALIDATOR_ID_PREFIX . $firewallName;
        $container
            ->setDefinition(
                $authenticatorAttestationResponseValidatorId,
                new Definition(AuthenticatorAttestationResponseValidator::class)
            )
            ->setArguments([new Reference($ceremonyStepManagerId)])
            ->addTag(EventDispatcherSetterCompilerPass::TAG)
        ;

        return $authenticatorAttestationResponseValidatorId;
    }
}
