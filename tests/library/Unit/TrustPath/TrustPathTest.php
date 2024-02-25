<?php

declare(strict_types=1);

namespace Webauthn\Tests\Unit\TrustPath;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Webauthn\Exception\InvalidTrustPathException;
use Webauthn\TrustPath\CertificateTrustPath;
use Webauthn\TrustPath\EmptyTrustPath;
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
        //When
        $tp = CertificateTrustPath::create(['cert#1']);

        //Then
        static::assertSame(['cert#1'], $tp->certificates);
    }

    /**
     * @use TrustPathLoader
     */
    #[Test]
    public function canLoadCertificateTrustPath(): void
    {
        //When
        $trustPath = TrustPathLoader::loadTrustPath([
            'x5c' => ['foo'],
        ]);

        //Then
        static::assertInstanceOf(CertificateTrustPath::class, $trustPath);
    }

    /**
     * @use TrustPathLoader
     */
    #[Test]
    public function canLoadEmptyTrustPath(): void
    {
        //When
        $trustPath = TrustPathLoader::loadTrustPath([]);

        //Then
        static::assertInstanceOf(EmptyTrustPath::class, $trustPath);
    }

    /**
     * @use TrustPathLoader
     */
    #[Test]
    public function cannotLoadUnknownTrustPath(): void
    {
        //Then
        $this->expectException(InvalidTrustPathException::class);
        $this->expectExceptionMessage('Invalid trust path');

        //When
        TrustPathLoader::loadTrustPath([
            'type' => NotAValidTrustPath::class,
        ]);
    }
}
