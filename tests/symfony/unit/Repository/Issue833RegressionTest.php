<?php

declare(strict_types=1);

namespace Webauthn\Tests\Bundle\Unit\Repository;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Config\FileLocator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader\PhpFileLoader;
use Symfony\Component\DependencyInjection\Reference;
use Webauthn\Bundle\Security\Authentication\WebauthnBadgeListener;

/**
 * Issue #833: when multiple security.providers are declared, Symfony does not create an
 * autowiring alias for UserProviderInterface, so WebauthnBadgeListener cannot be autowired
 * unless its $userProvider argument is wired explicitly to security.user_providers.
 *
 * @internal
 */
final class Issue833RegressionTest extends TestCase
{
    #[Test]
    public function webauthnBadgeListenerHasExplicitUserProviderArgument(): void
    {
        $container = new ContainerBuilder();
        $loader = new PhpFileLoader(
            $container,
            new FileLocator(__DIR__ . '/../../../../src/symfony/src/Resources/config')
        );
        $loader->load('security.php');

        static::assertTrue(
            $container->hasDefinition(WebauthnBadgeListener::class),
            'WebauthnBadgeListener should be registered by security.php.'
        );

        $definition = $container->getDefinition(WebauthnBadgeListener::class);
        $argument = $definition->getArgument('$userProvider');

        static::assertInstanceOf(Reference::class, $argument);
        static::assertSame(
            'security.user_providers',
            (string) $argument,
            'WebauthnBadgeListener::$userProvider must be wired to security.user_providers so that '
                . 'autowiring works even when multiple user providers are configured (issue #833).'
        );
    }
}
