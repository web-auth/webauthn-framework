<?php

declare(strict_types=1);

namespace Webauthn\Tests\Unit\TrustPath;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Webauthn\Exception\InvalidTrustPathException;
use Webauthn\TrustPath\CertificateTrustPath;
use Webauthn\TrustPath\TrustPathLoader;

/**
 * @internal
 */
final class TrustPathTest extends TestCase
{
    /**
     * @use CertificateTrustPath
     */
    #[Test]
    public function aCertificateTrustPathCanBeCreated(): void
    {
        $tp = CertificateTrustPath::create(['cert#1']);

        static::assertSame(['cert#1'], $tp->certificates);
    }

    /**
     * @use TrustPathLoader
     */
    #[Test]
    public function theLoaderCannotLoadUnsupportedTypeName(): void
    {
        $this->expectException(InvalidTrustPathException::class);
        $this->expectExceptionMessage('The trust path type "foo" is not supported');
        TrustPathLoader::loadTrustPath([
            'type' => 'foo',
        ]);
    }

    /**
     * @use TrustPathLoader
     */
    #[Test]
    public function theLoaderCannotLoadUnsupportedTypeNameBasedOnClass(): void
    {
        $this->expectException(InvalidTrustPathException::class);
        $this->expectExceptionMessage(
            'The trust path type "Webauthn\Tests\Unit\TrustPath\NotAValidTrustPath" is not supported'
        );
        TrustPathLoader::loadTrustPath([
            'type' => NotAValidTrustPath::class,
        ]);
    }
}
