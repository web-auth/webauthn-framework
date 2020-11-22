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
use Webauthn\AttestationStatement\AppleAttestationStatementSupport;

/**
 * @group unit
 * @group Fido2
 *
 * @covers \Webauthn\AttestationStatement\AppleAttestationStatementSupport
 *
 * @internal
 */
class AppleAttestationStatementSupportTest extends TestCase
{
    use ProphecyTrait;

    /**
     * @test
     */
    public function theAttestationStatementDoesNotContainTheRequiredCertificateList(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The attestation statement value "x5c" is missing.');
        $support = new AppleAttestationStatementSupport();
        static::assertFalse($support->load([
            'fmt' => 'apple',
            'attStmt' => [
                'sig' => 'foo-bar',
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
        $support = new AppleAttestationStatementSupport();

        static::assertEquals('apple', $support->name());
        static::assertFalse($support->load([
            'fmt' => 'apple',
            'attStmt' => [
                'sig' => 'foo-bar',
                'x5c' => [],
                'alg' => -7,
            ],
        ]));
    }
}
