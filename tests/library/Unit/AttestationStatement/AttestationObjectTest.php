<?php

declare(strict_types=1);

namespace Webauthn\Tests\Unit\AttestationStatement;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Webauthn\AttestationStatement\AttestationObject;
use Webauthn\AttestationStatement\AttestationStatement;
use Webauthn\AuthenticatorData;
use Webauthn\TrustPath\EmptyTrustPath;

/**
 * @internal
 */
final class AttestationObjectTest extends TestCase
{
    #[Test]
    public function creatingAttestationObjectPreservesAllProperties(): void
    {
        // Given
        $attestationStatement = AttestationStatement::create('', [], '', emptyTrustPath::create());
        $authenticatorData = AuthenticatorData::create('', '', '', 0);

        // When
        $object = AttestationObject::create('rawAttestationObject', $attestationStatement, $authenticatorData);

        // Then
        static::assertSame('rawAttestationObject', $object->rawAttestationObject);
        static::assertInstanceOf(AttestationStatement::class, $object->attStmt);
        static::assertInstanceOf(AuthenticatorData::class, $object->authData);
    }
}
