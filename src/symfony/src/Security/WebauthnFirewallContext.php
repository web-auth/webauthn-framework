<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Security;

use function array_key_exists;
use InvalidArgumentException;
use function sprintf;

final class WebauthnFirewallContext
{
    /**
     * @param array<string,WebauthnFirewallConfig> $firewallConfigs
     */
    public function __construct(
        private array $firewallConfigs
    ) {
    }

    public function getFirewallConfig(string $firewallName): WebauthnFirewallConfig
    {
        if (! array_key_exists($firewallName, $this->firewallConfigs)) {
            throw new InvalidArgumentException(sprintf('Firewall "%s" has no webauthn config.', $firewallName));
        }

        return $this->firewallConfigs[$firewallName];
    }
}
