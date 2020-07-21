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
use Prophecy\PhpUnit\ProphecyTrait;
use Webauthn\AttestationStatement\AttestationObject;
use Webauthn\AttestationStatement\AttestationStatement;
use Webauthn\AuthenticatorData;

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
    use ProphecyTrait;

    /**
     * @test
     */
    public function anAttestationObjectCanBeCreated(): void
    {
        $attestationStatement = $this->prophesize(AttestationStatement::class);
        $authenticatorData = $this->prophesize(AuthenticatorData::class);

        $object = new AttestationObject(
            'rawAttestationObject',
            $attestationStatement->reveal(),
            $authenticatorData->reveal()
        );

        static::assertEquals('rawAttestationObject', $object->getRawAttestationObject());
        static::assertInstanceOf(AttestationStatement::class, $object->getAttStmt());
        static::assertInstanceOf(AuthenticatorData::class, $object->getAuthData());
    }
}
