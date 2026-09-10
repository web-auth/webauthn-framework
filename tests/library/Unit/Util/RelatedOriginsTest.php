<?php

declare(strict_types=1);

namespace Webauthn\Tests\Unit\Util;

use Pdp\Rules;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Webauthn\Util\PdpPublicSuffixResolver;
use Webauthn\Util\PublicSuffixResolver;
use Webauthn\Util\RelatedOrigins;

/**
 * Related Origin Requests are capped by the client to 5 distinct eTLD+1 labels (WebAuthn Level 3). The label of an
 * origin is the one immediately preceding its public suffix, so "example.com" and "example.co.uk" share the label
 * "example" and count once.
 *
 * @internal
 *
 * @see https://www.w3.org/TR/webauthn-3/#sctn-related-origins
 */
final class RelatedOriginsTest extends TestCase
{
    private const PUBLIC_SUFFIX_LIST = <<<'PSL'
        // ===BEGIN ICANN DOMAINS===
        com
        de
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
    public static function origins(): iterable
    {
        yield 'simple origin' => ['https://example.com', 'example'];
        yield 'origin with a port' => ['https://example.com:8443', 'example'];
        yield 'origin with a path' => ['https://example.com/foo/bar', 'example'];
        yield 'subdomain' => ['https://login.example.com', 'example'];
        yield 'deep subdomain' => ['https://a.b.c.example.com', 'example'];
        yield 'multi label public suffix' => ['https://example.co.uk', 'example'];
        yield 'subdomain of a multi label public suffix' => ['https://login.example.co.uk', 'example'];
        yield 'private section public suffix' => ['https://example.github.io', 'example'];
        yield 'host only entry' => ['example.com', 'example'];
        yield 'http origin' => ['http://example.com', 'example'];
        yield 'uppercase host' => ['https://EXAMPLE.COM', 'example'];
        yield 'trailing dot' => ['https://example.com.', 'example'];
        yield 'single label host' => ['https://localhost', null];
        yield 'single label host with a port' => ['https://localhost:8443', null];
        yield 'public suffix only' => ['https://co.uk', null];
        yield 'IPv4 literal' => ['https://127.0.0.1', null];
        yield 'IPv6 literal' => ['https://[::1]', null];
        yield 'android facet identifier' => ['android:apk-key-hash:9Aa1b2C3d4E5f6', null];
        yield 'empty origin' => ['', null];
    }

    #[Test]
    #[DataProvider('origins')]
    public function theLabelOfAnOriginIsCorrectlyExtracted(string $origin, ?string $expectedLabel): void
    {
        static::assertSame($expectedLabel, self::relatedOrigins()->getLabel($origin));
    }

    #[Test]
    public function distinctLabelsAreCollectedInOrderAndDeduplicated(): void
    {
        static::assertSame(['example', 'acme'], self::relatedOrigins()->getDistinctLabels([
            'https://example.com',
            'https://login.example.com',
            'https://example.co.uk',
            'https://localhost',
            'https://acme.com',
        ]));
    }

    #[Test]
    public function aListWithinTheLimitIsAccepted(): void
    {
        $origins = [
            'https://a.com',
            'https://b.com',
            'https://c.com',
            'https://d.com',
            'https://e.com',
            'https://www.e.com',
            'https://e.co.uk',
        ];
        $relatedOrigins = self::relatedOrigins();

        static::assertFalse($relatedOrigins->exceedsLabelLimit($origins));
        static::assertSame([], $relatedOrigins->getIgnoredOrigins($origins));
    }

    #[Test]
    public function originsBeyondTheFifthDistinctLabelAreReportedAsIgnored(): void
    {
        $origins = [
            'https://a.com',
            'https://b.com',
            'https://c.com',
            'https://d.com',
            'https://e.com',
            'https://f.com',
            'https://www.a.com',
            'https://g.co.uk',
        ];
        $relatedOrigins = self::relatedOrigins();

        static::assertTrue($relatedOrigins->exceedsLabelLimit($origins));
        static::assertSame(['https://f.com', 'https://g.co.uk'], $relatedOrigins->getIgnoredOrigins($origins));
    }

    #[Test]
    public function theLimitCountsLabelsAndNotOrigins(): void
    {
        $origins = [
            'https://example.com',
            'https://example.co.uk',
            'https://example.fr',
            'https://login.example.com',
            'https://example.com:8443',
            'https://admin.example.de',
        ];
        $relatedOrigins = self::relatedOrigins();

        static::assertSame(['example'], $relatedOrigins->getDistinctLabels($origins));
        static::assertFalse($relatedOrigins->exceedsLabelLimit($origins));
    }

    #[Test]
    public function anyPublicSuffixResolverImplementationCanBePluggedIn(): void
    {
        $resolver = new class() implements PublicSuffixResolver {
            public function getPublicSuffix(string $host): string
            {
                return 'internal.example';
            }
        };

        static::assertSame('shop', RelatedOrigins::create($resolver)->getLabel('https://shop.internal.example'));
    }

    #[Test]
    public function aResolverReturningASuffixThatIsNotPartOfTheHostIsIgnored(): void
    {
        $resolver = new class() implements PublicSuffixResolver {
            public function getPublicSuffix(string $host): string
            {
                return 'somewhere.else';
            }
        };

        static::assertNull(RelatedOrigins::create($resolver)->getLabel('https://example.com'));
    }

    private static function relatedOrigins(): RelatedOrigins
    {
        return RelatedOrigins::create(PdpPublicSuffixResolver::create(Rules::fromString(self::PUBLIC_SUFFIX_LIST)));
    }
}
