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

namespace Webauthn\Tests\Unit\AttestationStatement;

use CBOR\Decoder;
use CBOR\OtherObject\OtherObjectManager;
use CBOR\Tag\TagObjectManager;
use PHPUnit\Framework\TestCase;
use Webauthn\AttestationStatement\AndroidKeyAttestationStatementSupport;

/**
 * @group unit
 * @group Fido2
 *
 * @covers \Webauthn\AttestationStatement\AndroidKeyAttestationStatementSupport
 */
class AndroidKeyAttestationStatementSupportTest extends TestCase
{
    /**
     * @test
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage The attestation statement value "sig" is missing.
     */
    public function theAttestationStatementDoesNotContainTheRequiredSignature(): void
    {
        $support = new AndroidKeyAttestationStatementSupport($this->getDecoder());

        static::assertEquals('android-key', $support->name());
        static::assertFalse($support->load([
            'fmt' => 'android-key',
            'attStmt' => [],
        ]));
    }

    /**
     * @test
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage The attestation statement value "x5c" is missing.
     */
    public function theAttestationStatementDoesNotContainTheRequiredCertificateList(): void
    {
        $support = new AndroidKeyAttestationStatementSupport($this->getDecoder());
        static::assertFalse($support->load([
            'fmt' => 'android-key',
            'attStmt' => [
                'sig' => 'foo-bar',
            ],
        ]));
    }

    /**
     * @test
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage The attestation statement value "alg" is missing.
     */
    public function theAttestationStatementDoesNotContainTheRequiredAlgorithmParameter(): void
    {
        $support = new AndroidKeyAttestationStatementSupport($this->getDecoder());
        static::assertFalse($support->load([
            'fmt' => 'android-key',
            'attStmt' => [
                'sig' => 'foo-bar',
                'x5c' => [],
            ],
        ]));
    }

    /**
     * @test
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage The attestation statement value "x5c" must be a list with at least one certificate.
     */
    public function theAttestationStatementContainsAnEmptyCertificateList(): void
    {
        $support = new AndroidKeyAttestationStatementSupport($this->getDecoder());

        static::assertEquals('android-key', $support->name());
        static::assertFalse($support->load([
            'fmt' => 'android-key',
            'attStmt' => [
                'sig' => 'foo-bar',
                'x5c' => [],
                'alg' => -7,
            ],
        ]));
    }

    private function getDecoder(): Decoder
    {
        return new Decoder(
            new TagObjectManager(),
            new OtherObjectManager()
        );
    }
}
