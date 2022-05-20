<?php

declare(strict_types=1);

namespace Webauthn\Bundle\DependencyInjection\Factory\Security;

use Symfony\Component\DependencyInjection\ChildDefinition;
use Symfony\Component\DependencyInjection\ContainerBuilder;

/**
 * @internal Helper class for WebauthnFactory only
 *
 * @final
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
            ->replaceArgument(1, $firewallName)
        ;

        return $firewallConfigId;
    }
}
