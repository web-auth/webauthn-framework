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

use PHPUnit\Framework\TestCase;
use Webauthn\AttestationStatement\AndroidKeyAttestationStatementSupport;
use Webauthn\Exception\InvalidAttestationStatementException;

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
    /**
     * @test
     */
    public function theAttestationStatementDoesNotContainTheRequiredSignature(): void
    {
        $this->expectException(InvalidAttestationStatementException::class);
        $this->expectExceptionMessage('The attestation statement is invalid');
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
        $this->expectException(InvalidAttestationStatementException::class);
        $this->expectExceptionMessage('The attestation statement is invalid');
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
        $this->expectException(InvalidAttestationStatementException::class);
        $this->expectExceptionMessage('The attestation statement is invalid');
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
        $this->expectException(InvalidAttestationStatementException::class);
        $this->expectExceptionMessage('The attestation statement is invalid');
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
