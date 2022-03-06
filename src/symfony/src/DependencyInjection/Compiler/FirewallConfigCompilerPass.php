<?php

declare(strict_types=1);

namespace Webauthn\Bundle\DependencyInjection\Compiler;

use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Exception\InvalidArgumentException;
use Symfony\Component\DependencyInjection\Reference;
use Webauthn\Bundle\DependencyInjection\Factory\Security\WebauthnFactory;

/**
 * Collect registered firewall configs and add them to the context.
 */
final class FirewallConfigCompilerPass implements CompilerPassInterface
{
    public const SERVICE_TAG = 'webauthn.firewall_config';

    public const ATTRIBUTE_NAME = 'firewall';

    public function process(ContainerBuilder $container): void
    {
        if (! $container->hasDefinition(WebauthnFactory::FIREWALL_CONTEXT_DEFINITION_ID)) {
            return;
        }

        $firewallContextDefinition = $container->getDefinition(WebauthnFactory::FIREWALL_CONTEXT_DEFINITION_ID);
        $taggedServices = $container->findTaggedServiceIds(self::SERVICE_TAG);

        $references = [];
        foreach ($taggedServices as $id => $attributes) {
            if (! isset($attributes[0][self::ATTRIBUTE_NAME])) {
                throw new InvalidArgumentException(sprintf(
                    'Tag "%s" requires attribute "%s" to be set.',
                    self::SERVICE_TAG,
                    self::ATTRIBUTE_NAME
                ));
            }

            $name = $attributes[0][self::ATTRIBUTE_NAME];
            $references[$name] = new Reference($id);
        }

        $firewallContextDefinition->replaceArgument(0, $references);
    }
}
