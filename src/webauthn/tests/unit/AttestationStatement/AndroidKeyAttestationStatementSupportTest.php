<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2020 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Webauthn\Tests\Unit\AttestationStatement;

use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use Prophecy\PhpUnit\ProphecyTrait;
use Webauthn\AttestationStatement\AndroidKeyAttestationStatementSupport;

/**
 * @group unit
 * @group Fido2
 *
 * @covers \Webauthn\AttestationStatement\AndroidKeyAttestationStatementSupport
 *
 * @internal
 */
class AndroidKeyAttestationStatementSupportTest extends TestCase
{
    use ProphecyTrait;

    /**
     * @test
     */
    public function theAttestationStatementDoesNotContainTheRequiredSignature(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The attestation statement value "sig" is missing.');
        $support = new AndroidKeyAttestationStatementSupport();

        static::assertEquals('android-key', $support->name());
        static::assertFalse($support->load([
            'fmt' => 'android-key',
            'attStmt' => [],
        ]));
    }

    /**
     * @test
     */
    public function theAttestationStatementDoesNotContainTheRequiredCertificateList(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The attestation statement value "x5c" is missing.');
        $support = new AndroidKeyAttestationStatementSupport();
        static::assertFalse($support->load([
            'fmt' => 'android-key',
            'attStmt' => [
                'sig' => 'foo-bar',
            ],
        ]));
    }

    /**
     * @test
     */
    public function theAttestationStatementDoesNotContainTheRequiredAlgorithmParameter(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The attestation statement value "alg" is missing.');
        $support = new AndroidKeyAttestationStatementSupport();
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
     */
    public function theAttestationStatementContainsAnEmptyCertificateList(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The attestation statement value "x5c" must be a list with at least one certificate.');
        $support = new AndroidKeyAttestationStatementSupport();

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
}
