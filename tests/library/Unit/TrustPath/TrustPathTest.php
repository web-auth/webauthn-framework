<?php

declare(strict_types=1);

namespace Webauthn\Tests\Unit\TrustPath;

use const JSON_THROW_ON_ERROR;
use PHPUnit\Framework\TestCase;
use Webauthn\Exception\InvalidTrustPathException;
use Webauthn\TrustPath\CertificateTrustPath;
use Webauthn\TrustPath\EcdaaKeyIdTrustPath;
use Webauthn\TrustPath\TrustPathLoader;

/**
 * @internal
 */
final class TrustPathTest extends TestCase
{
    /**
     * @test
     *
     * @use CertificateTrustPath
     */
    public function aCertificateTrustPathCanBeCreated(): void
    {
        $tp = CertificateTrustPath::create(['cert#1']);

        static::assertSame(['cert#1'], $tp->getCertificates());
    }

    /**
     * @test
     *
     * @use EcdaaKeyIdTrustPath
     */
    public function anEcdaaKeyIdTrustPathCanBeCreated(): void
    {
        $tp = new EcdaaKeyIdTrustPath('id');

        static::assertSame('id', $tp->getEcdaaKeyId());
    }

    /**
     * @test
     *
     * @use TrustPathLoader
     */
    public function theLoaderCanLoadCustomTrustPath(): void
    {
        $trustPath = json_encode(new FooTrustPath(), JSON_THROW_ON_ERROR);
        $data = json_decode($trustPath, true, 512, JSON_THROW_ON_ERROR);
        $loadedTrustPath = TrustPathLoader::loadTrustPath($data);

        static::assertInstanceOf(FooTrustPath::class, $loadedTrustPath);
    }

    /**
     * @test
     *
     * @use TrustPathLoader
     */
    public function theLoaderCannotLoadUnsupportedTypeName(): void
    {
        $this->expectException(InvalidTrustPathException::class);
        $this->expectExceptionMessage('The trust path type "foo" is not supported');
        TrustPathLoader::loadTrustPath([
            'type' => 'foo',
        ]);
    }

    /**
     * @test
     *
     * @use TrustPathLoader
     */
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

    /**
     * @test
     *
     * @use TrustPathLoader
     */
    public function theLoaderCanLoadNewTrustPathType(): void
    {
        $trustPath = json_encode(new EcdaaKeyIdTrustPath('key_id'), JSON_THROW_ON_ERROR);
        $data = json_decode($trustPath, true, 512, JSON_THROW_ON_ERROR);
        $loadedTrustPath = TrustPathLoader::loadTrustPath($data);

        static::assertInstanceOf(EcdaaKeyIdTrustPath::class, $loadedTrustPath);
        static::assertSame('key_id', $loadedTrustPath->getEcdaaKeyId());
    }
}
