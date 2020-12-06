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
use Webauthn\AttestationStatement\AttestationObject;
use Webauthn\AttestationStatement\AttestationStatement;
use Webauthn\AuthenticatorData;
use Webauthn\TrustPath\EmptyTrustPath;

/**
 * @group unit
 * @group Fido2
 *
 * @covers \Webauthn\AttestationStatement\AttestationObject
 *
 * @internal
 */
class AttestationObjectTest extends TestCase
{
    /**
     * @test
     */
    public function anAttestationObjectCanBeCreated(): void
    {
        $attestationStatement = new AttestationStatement('', [], '', new EmptyTrustPath());
        $authenticatorData = new AuthenticatorData('', '', '', 0, null, null);

        $object = new AttestationObject(
            'rawAttestationObject',
            $attestationStatement,
            $authenticatorData
        );

        static::assertEquals('rawAttestationObject', $object->getRawAttestationObject());
        static::assertInstanceOf(AttestationStatement::class, $object->getAttStmt());
        static::assertInstanceOf(AuthenticatorData::class, $object->getAuthData());
    }
}
