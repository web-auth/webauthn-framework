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

use PHPUnit\Framework\TestCase;
use Webauthn\AttestationStatement\AttestationStatement;
use Webauthn\AttestationStatement\NoneAttestationStatementSupport;
use Webauthn\AuthenticatorData;

/**
 * @group unit
 * @group Fido2
 *
 * @covers \Webauthn\AttestationStatement\NoneAttestationStatementSupport
 */
class NoneAttestationStatementSupportTest extends TestCase
{
    /**
     * @test
     */
    public function theAttestationStatementIsNotValid(): void
    {
        $support = new NoneAttestationStatementSupport();

        $attestationStatement = $this->prophesize(AttestationStatement::class);
        $attestationStatement->getAttStmt()->willReturn([]);
        $authenticatorData = $this->prophesize(AuthenticatorData::class);

        static::assertEquals('none', $support->name());
        static::assertTrue($support->isValid('FOO', $attestationStatement->reveal(), $authenticatorData->reveal()));
    }

    /**
     * @test
     */
    public function theAttestationStatementIsValid(): void
    {
        $support = new NoneAttestationStatementSupport();

        $attestationStatement = $this->prophesize(AttestationStatement::class);
        $attestationStatement->getAttStmt()->willReturn([
            'x5c' => ['FOO'],
        ]);
        $authenticatorData = $this->prophesize(AuthenticatorData::class);

        static::assertEquals('none', $support->name());
        static::assertFalse($support->isValid('FOO', $attestationStatement->reveal(), $authenticatorData->reveal()));
    }
}
