<?php

declare(strict_types=1);

namespace Webauthn\Tests\Bundle\Unit\DependencyInjection\Compiler;

use Pdp\Rules;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use Stringable;
use Symfony\Component\Config\Definition\Processor;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Webauthn\Bundle\CacheWarmer\RelatedOriginsLabelLimitWarmer;
use Webauthn\Bundle\Controller\AllowedOriginsController;
use Webauthn\Bundle\DependencyInjection\Compiler\CeremonyStepManagerFactoryCompilerPass;
use Webauthn\Bundle\DependencyInjection\Configuration;
use Webauthn\Bundle\Routing\Loader;
use Webauthn\CeremonyStep\CeremonyStepManagerFactory;
use Webauthn\Util\PdpPublicSuffixResolver;
use Webauthn\Util\PublicSuffixResolver;

/**
 * The "/.well-known/webauthn" endpoint may advertise as many origins as needed, but clients only process the first 5
 * distinct eTLD+1 labels (WebAuthn Level 3, Related Origin Requests). Exceeding that cap is a configuration mistake
 * that silently disables the extra origins, so the bundle warns about it. It does not throw: an existing application
 * must keep booting, and a developer aware of the trade-off can opt out with
 * "webauthn.related_origins.label_limit_check".
 *
 * The check needs public suffix data, which the library does not ship, so it only runs when the application
 * registered a "Webauthn\Util\PublicSuffixResolver" service.
 *
 * @internal
 *
 * @see https://www.w3.org/TR/webauthn-3/#sctn-related-origins
 */
final class RelatedOriginsLabelLimitTest extends TestCase
{
    private const TOO_MANY_LABELS = [
        'https://one.com',
        'https://two.com',
        'https://three.com',
        'https://four.com',
        'https://five.com',
        'https://six.com',
    ];

    private const PUBLIC_SUFFIX_LIST = <<<'PSL'
        // ===BEGIN ICANN DOMAINS===
        com
        uk
        co.uk
        // ===END ICANN DOMAINS===
        PSL;

    #[Test]
    public function theCheckIsEnabledByDefaultAndHasNoResolverByDefault(): void
    {
        $config = (new Processor())->processConfiguration(new Configuration('webauthn'), [[]]);

        static::assertTrue($config['related_origins']['label_limit_check']);
        static::assertNull($config['related_origins']['public_suffix_resolver']);
    }

    #[Test]
    public function theWarmerIsRegisteredWhenAResolverIsAvailable(): void
    {
        $container = $this->compile(self::TOO_MANY_LABELS, true, true);

        static::assertTrue($container->hasDefinition(RelatedOriginsLabelLimitWarmer::class));
        static::assertTrue($container->getDefinition(RelatedOriginsLabelLimitWarmer::class)->hasTag(
            'kernel.cache_warmer'
        ));
    }

    #[Test]
    public function theWarmerIsNotRegisteredWithoutAResolver(): void
    {
        $container = $this->compile(self::TOO_MANY_LABELS, true, false);

        static::assertFalse($container->hasDefinition(RelatedOriginsLabelLimitWarmer::class));
        static::assertTrue($container->hasDefinition(AllowedOriginsController::class));
    }

    #[Test]
    public function theCheckCanBeOptedOut(): void
    {
        $container = $this->compile(self::TOO_MANY_LABELS, false, true);

        static::assertFalse($container->hasDefinition(RelatedOriginsLabelLimitWarmer::class));
    }

    #[Test]
    public function aWarningIsLoggedWhenTheLabelLimitIsExceeded(): void
    {
        $warning = null;
        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects(static::once())
            ->method('warning')
            ->willReturnCallback(static function (string|Stringable $message) use (&$warning): void {
                $warning = (string) $message;
            });
        $warmer = new RelatedOriginsLabelLimitWarmer(self::TOO_MANY_LABELS, $this->resolver(), $logger);

        static::assertSame([], $warmer->warmUp('/tmp'));
        static::assertTrue($warmer->isOptional());
        static::assertIsString($warning);
        static::assertStringContainsString('https://six.com', $warning);
        static::assertStringContainsString('6 distinct eTLD+1 labels', $warning);
    }

    #[Test]
    public function nothingIsLoggedWhenTheOriginsStayWithinTheLimit(): void
    {
        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects(static::never())
            ->method('warning');
        $warmer = new RelatedOriginsLabelLimitWarmer([
            'https://example.com',
            'https://example.co.uk',
            'https://login.example.com',
            'https://localhost',
        ], $this->resolver(), $logger);

        static::assertSame([], $warmer->warmUp('/tmp'));
    }

    private function resolver(): PublicSuffixResolver
    {
        return PdpPublicSuffixResolver::create(Rules::fromString(self::PUBLIC_SUFFIX_LIST));
    }

    /**
     * @param array<string> $allowedOrigins
     */
    private function compile(array $allowedOrigins, bool $labelLimitCheck, bool $withResolver): ContainerBuilder
    {
        $container = new ContainerBuilder();
        $container->setDefinition(CeremonyStepManagerFactory::class, new Definition(CeremonyStepManagerFactory::class));
        $container->setDefinition(Loader::class, new Definition(Loader::class));
        $container->setParameter('webauthn.allowed_origins', $allowedOrigins);
        $container->setParameter('webauthn.allow_subdomains', false);
        $container->setParameter('webauthn.related_origins.label_limit_check', $labelLimitCheck);
        if ($withResolver) {
            $container->setDefinition(PublicSuffixResolver::class, new Definition(PdpPublicSuffixResolver::class));
        }

        (new CeremonyStepManagerFactoryCompilerPass())->process($container);

        return $container;
    }
}
