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
use Webauthn\AttestationStatement\AttestationStatement;
use Webauthn\AttestationStatement\NoneAttestationStatementSupport;
use Webauthn\AuthenticatorData;
use Webauthn\TrustPath\EmptyTrustPath;

/**
 * @group unit
 * @group Fido2
 *
 * @covers \Webauthn\AttestationStatement\NoneAttestationStatementSupport
 *
 * @internal
 */
class NoneAttestationStatementSupportTest extends TestCase
{
    /**
     * @test
     */
    public function theAttestationStatementIsNotValid(): void
    {
        $support = new NoneAttestationStatementSupport();

        $attestationStatement = new AttestationStatement('none', [], '', EmptyTrustPath::create());
        $authenticatorData = new AuthenticatorData('', '', '', 0, null, null);

        static::assertEquals('none', $support->name());
        static::assertTrue($support->isValid('FOO', $attestationStatement, $authenticatorData));
    }

    /**
     * @test
     */
    public function theAttestationStatementIsValid(): void
    {
        $support = new NoneAttestationStatementSupport();

        $attestationStatement = new AttestationStatement('none', ['x5c' => ['FOO']], '', EmptyTrustPath::create());
        $authenticatorData = new AuthenticatorData('', '', '', 0, null, null);

        static::assertEquals('none', $support->name());
        static::assertFalse($support->isValid('FOO', $attestationStatement, $authenticatorData));
    }
}
