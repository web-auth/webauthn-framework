<?php

declare(strict_types=1);

namespace Webauthn\Tests\Unit\TrustPath;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Webauthn\Exception\InvalidTrustPathException;
use Webauthn\TrustPath\CertificateTrustPath;
use Webauthn\TrustPath\EcdaaKeyIdTrustPath;
use Webauthn\TrustPath\TrustPathLoader;
use const JSON_THROW_ON_ERROR;

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
     * @use EcdaaKeyIdTrustPath
     */
    #[Test]
    public function anEcdaaKeyIdTrustPathCanBeCreated(): void
    {
        $tp = new EcdaaKeyIdTrustPath('id');

        static::assertSame('id', $tp->getEcdaaKeyId());
    }

    /**
     * @use TrustPathLoader
     */
    #[Test]
    public function theLoaderCannotLoadUnsupportedTypeName(): void
    {
        $this->expectException(InvalidTrustPathException::class);
        $this->expectExceptionMessage('Unsupported trust path');
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
        $this->expectExceptionMessage('Unsupported trust path');
        TrustPathLoader::loadTrustPath([
            'type' => NotAValidTrustPath::class,
        ]);
    }

    /**
     * @use TrustPathLoader
     */
    #[Test]
    public function theLoaderCanLoadNewTrustPathType(): void
    {
        $trustPath = json_encode(new EcdaaKeyIdTrustPath('key_id'), JSON_THROW_ON_ERROR);
        $data = json_decode($trustPath, true, 512, JSON_THROW_ON_ERROR);
        $loadedTrustPath = TrustPathLoader::loadTrustPath($data);

        static::assertInstanceOf(EcdaaKeyIdTrustPath::class, $loadedTrustPath);
        static::assertSame('key_id', $loadedTrustPath->getEcdaaKeyId());
    }
}
