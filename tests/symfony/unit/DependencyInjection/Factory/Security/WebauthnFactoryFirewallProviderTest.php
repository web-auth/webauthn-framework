<?php

declare(strict_types=1);

namespace Webauthn\Tests\Bundle\Unit\DependencyInjection\Factory\Security;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use ReflectionMethod;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Reference;
use Webauthn\Bundle\DependencyInjection\Factory\Security\WebauthnFactory;
use Webauthn\Bundle\DependencyInjection\Factory\Security\WebauthnServicesFactory;

/**
 * Documents Path 2 of the user-provider resolution: when the bundle's `webauthn:` firewall is
 * used, the authenticator created for that firewall MUST receive the firewall's configured
 * `provider:` (resolved by Symfony's security framework into a service id), not the global chain.
 *
 * The factory is the seam where Symfony hands off the per-firewall provider to the bundle, so we
 * test it at that exact boundary.
 *
 * @internal
 */
final class WebauthnFactoryFirewallProviderTest extends TestCase
{
    #[Test]
    public function authenticatorServiceReceivesTheFirewallSpecificUserProvider(): void
    {
        $container = $this->containerWithAuthenticatorTemplate();
        $factory = new WebauthnFactory(new WebauthnServicesFactory());

        $authenticatorId = $this->invokeCreateAuthenticatorService(
            $factory,
            $container,
            firewallName: 'admin',
            userProviderId: 'security.user.provider.concrete.admin_provider',
        );

        $definition = $container->getDefinition($authenticatorId);
        $userProviderArgument = $definition->getArgument(1);

        static::assertInstanceOf(Reference::class, $userProviderArgument);
        static::assertSame(
            'security.user.provider.concrete.admin_provider',
            (string) $userProviderArgument,
            'WebauthnFactory must wire the firewall-scoped user provider as argument #1 of the authenticator service.',
        );
    }

    #[Test]
    public function eachFirewallGetsAnAuthenticatorBoundToItsOwnUserProvider(): void
    {
        // Multi-firewall scenario, the same one #833 reported (back-end + front-end providers).
        $container = $this->containerWithAuthenticatorTemplate();
        $factory = new WebauthnFactory(new WebauthnServicesFactory());

        $backendId = $this->invokeCreateAuthenticatorService(
            $factory,
            $container,
            firewallName: 'backend',
            userProviderId: 'security.user.provider.concrete.backend',
        );
        $frontendId = $this->invokeCreateAuthenticatorService(
            $factory,
            $container,
            firewallName: 'frontend',
            userProviderId: 'security.user.provider.concrete.frontend',
        );

        static::assertNotSame($backendId, $frontendId, 'Each firewall must get its own authenticator service.');
        static::assertSame(
            'security.user.provider.concrete.backend',
            (string) $container->getDefinition($backendId)
                ->getArgument(1),
        );
        static::assertSame(
            'security.user.provider.concrete.frontend',
            (string) $container->getDefinition($frontendId)
                ->getArgument(1),
        );
    }

    private function invokeCreateAuthenticatorService(
        WebauthnFactory $factory,
        ContainerBuilder $container,
        string $firewallName,
        string $userProviderId,
    ): string {
        // The public createAuthenticator() pulls in route/controller side-effects that are out of
        // scope for this test. createAuthenticatorService() is the private seam that wires the
        // user-provider argument; reach it via reflection.
        $method = new ReflectionMethod(WebauthnFactory::class, 'createAuthenticatorService');

        return $method->invoke(
            $factory,
            $container,
            $firewallName,
            $userProviderId,
            'success.handler.id',
            'failure.handler.id',
            'firewall.config.id',
            null,
            'assertion.validator.id',
            'attestation.validator.id',
        );
    }

    private function containerWithAuthenticatorTemplate(): ContainerBuilder
    {
        // The factory adds ChildDefinitions of WebauthnFactory::AUTHENTICATOR_DEFINITION_ID; the
        // template must therefore exist in the container, even if we never compile it.
        $container = new ContainerBuilder();
        $container->setDefinition(
            WebauthnFactory::AUTHENTICATOR_DEFINITION_ID,
            (new Definition())->setAbstract(true),
        );

        return $container;
    }
}
