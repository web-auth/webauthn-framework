<?php

declare(strict_types=1);

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
        $attestationStatement = new AttestationStatement('', [], '', EmptyTrustPath::create());
        $authenticatorData = AuthenticatorData::create('', '', '', 0, null, null);

        $object = AttestationObject::create(
            'rawAttestationObject',
            $attestationStatement,
            $authenticatorData
        );

        static::assertEquals('rawAttestationObject', $object->getRawAttestationObject());
        static::assertInstanceOf(AttestationStatement::class, $object->getAttStmt());
        static::assertInstanceOf(AuthenticatorData::class, $object->getAuthData());
    }
}
