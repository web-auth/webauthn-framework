<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2019 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Webauthn\Tests\Unit\TrustPath;

use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use Webauthn\TrustPath\CertificateTrustPath;
use Webauthn\TrustPath\EcdaaKeyIdTrustPath;
use Webauthn\TrustPath\TrustPathLoader;

/**
 * @group unit
 * @group Fido2
 */
class TrustPathTest extends TestCase
{
    /**
     * @test
     *
     * @use \Webauthn\TrustPath\TrustPath\CertificateTrustPath
     */
    public function aCertificateTrustPathCanBeCreated(): void
    {
        $tp = new CertificateTrustPath(['cert#1']);

        static::assertEquals(['cert#1'], $tp->getCertificates());
    }

    /**
     * @test
     *
     * @use \Webauthn\TrustPath\TrustPath\EcdaaKeyIdTrustPath
     */
    public function anEcdaaKeyIdTrustPathCanBeCreated(): void
    {
        $tp = new EcdaaKeyIdTrustPath('id');

        static::assertEquals('id', $tp->getEcdaaKeyId());
    }

    /**
     * @test
     *
     * @use \Webauthn\TrustPath\TrustPath\TrustPathLoader
     */
    public function theLoaderCanLoadCustomTrustPath(): void
    {
        $trustPath = json_encode(new FooTrustPath());
        $data = json_decode($trustPath, true);
        $loadedTrustPath = TrustPathLoader::loadTrustPath($data);

        static::assertInstanceOf(FooTrustPath::class, $loadedTrustPath);
    }

    /**
     * @test
     *
     * @use \Webauthn\TrustPath\TrustPath\TrustPathLoader
     */
    public function theLoaderCannotLoadUnsupportedTypeName(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The trust path type "foo" is not supported');
        TrustPathLoader::loadTrustPath([
            'type' => 'foo',
        ]);
    }

    /**
     * @test
     *
     * @use \Webauthn\TrustPath\TrustPath\TrustPathLoader
     */
    public function theLoaderCannotLoadUnsupportedTypeNameBasedOnClass(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The trust path type "Webauthn\Tests\Unit\TrustPath\NotAValidTrustPath" is not supported');
        TrustPathLoader::loadTrustPath([
            'type' => NotAValidTrustPath::class,
        ]);
    }

    /**
     * @test
     *
     * @use \Webauthn\TrustPath\TrustPath\TrustPathLoader
     */
    public function theLoaderCanLoadOldTrustPathType(): void
    {
        $loadedTrustPath = TrustPathLoader::loadTrustPath([
            'type' => 'ecdaa_key_id',
            'ecdaaKeyId' => 'key_id',
        ]);

        static::assertInstanceOf(EcdaaKeyIdTrustPath::class, $loadedTrustPath);
        static::assertEquals('key_id', $loadedTrustPath->getEcdaaKeyId());
    }

    /**
     * @test
     *
     * @use \Webauthn\TrustPath\TrustPath\TrustPathLoader
     */
    public function theLoaderCanLoadNewTrustPathType(): void
    {
        $trustPath = json_encode(new EcdaaKeyIdTrustPath('key_id'));
        $data = json_decode($trustPath, true);
        $loadedTrustPath = TrustPathLoader::loadTrustPath($data);

        static::assertInstanceOf(EcdaaKeyIdTrustPath::class, $loadedTrustPath);
        static::assertEquals('key_id', $loadedTrustPath->getEcdaaKeyId());
    }
}
