<?php

declare(strict_types=1);

namespace Webauthn\Tests\Unit\Util;

use Pdp\Rules;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Webauthn\Util\PdpPublicSuffixResolver;

/**
 * The library ships no public suffix data: it only adapts the parser the application decided to use. This test pins
 * the adapter behaviour against a minimal Public Suffix List, including the entries a WebAuthn deployment cares about
 * (multi label suffixes and the private section).
 *
 * @internal
 */
final class PdpPublicSuffixResolverTest extends TestCase
{
    private const PUBLIC_SUFFIX_LIST = <<<'PSL'
        // ===BEGIN ICANN DOMAINS===
        com
        fr
        io
        uk
        co.uk
        // ===END ICANN DOMAINS===
        // ===BEGIN PRIVATE DOMAINS===
        github.io
        // ===END PRIVATE DOMAINS===
        PSL;

    /**
     * @return iterable<string, array{string, string|null}>
     */
    public static function hosts(): iterable
    {
        yield 'single label suffix' => ['example.com', 'com'];
        yield 'multi label suffix' => ['example.co.uk', 'co.uk'];
        yield 'suffix of a subdomain' => ['login.example.co.uk', 'co.uk'];
        yield 'private section suffix' => ['example.github.io', 'github.io'];
        yield 'unknown TLD falls back on the last label' => ['example.acme', 'acme'];
        yield 'uppercase host' => ['EXAMPLE.CO.UK', 'co.uk'];
        yield 'trailing dot' => ['example.com.', 'com'];
        yield 'the host is a public suffix' => ['co.uk', null];
        yield 'single label host' => ['localhost', null];
        yield 'IPv4 literal' => ['192.168.1.1', null];
        yield 'empty host' => ['', null];
    }

    #[Test]
    #[DataProvider('hosts')]
    public function thePublicSuffixIsResolved(string $host, ?string $expectedSuffix): void
    {
        $resolver = PdpPublicSuffixResolver::create(Rules::fromString(self::PUBLIC_SUFFIX_LIST));

        static::assertSame($expectedSuffix, $resolver->getPublicSuffix($host));
    }

    #[Test]
    public function anInvalidHostDoesNotBubbleUpAsAnException(): void
    {
        $resolver = PdpPublicSuffixResolver::create(Rules::fromString(self::PUBLIC_SUFFIX_LIST));

        static::assertNull($resolver->getPublicSuffix('.....'));
    }
}
