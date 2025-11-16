<?php

declare(strict_types=1);

namespace Webauthn\Tests\Unit\AttestationStatement;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Webauthn\AttestationStatement\AttestationStatement;
use Webauthn\TrustPath\CertificateTrustPath;
use Webauthn\TrustPath\EmptyTrustPath;

/**
 * @internal
 */
final class AttestationStatementTest extends TestCase
{
    #[Test]
    public function creatingNoneTypeAttestationStatementPreservesAllProperties(): void
    {
        // Given/When
        $attestationStatement = AttestationStatement::createNone('fmt', [
            'bar' => 'FOO',
        ], EmptyTrustPath::create());

        // Then
        static::assertSame('fmt', $attestationStatement->fmt);
        static::assertSame([
            'bar' => 'FOO',
        ], $attestationStatement->attStmt);
        static::assertTrue($attestationStatement->has('bar'));
        static::assertFalse($attestationStatement->has('foo'));
        static::assertSame('FOO', $attestationStatement->get('bar'));
        static::assertInstanceOf(EmptyTrustPath::class, $attestationStatement->trustPath);
        static::assertSame('none', $attestationStatement->type);
    }

    #[Test]
    public function creatingBasicTypeAttestationStatementPreservesAllProperties(): void
    {
        // Given/When
        $attestationStatement = AttestationStatement::createBasic('fmt', [
            'bar' => 'FOO',
        ], CertificateTrustPath::create(['key_id']));

        // Then
        static::assertSame('fmt', $attestationStatement->fmt);
        static::assertSame([
            'bar' => 'FOO',
        ], $attestationStatement->attStmt);
        static::assertTrue($attestationStatement->has('bar'));
        static::assertFalse($attestationStatement->has('foo'));
        static::assertSame('FOO', $attestationStatement->get('bar'));
        static::assertInstanceOf(CertificateTrustPath::class, $attestationStatement->trustPath);
        static::assertSame('basic', $attestationStatement->type);
    }

    #[Test]
    public function creatingAttCATypeAttestationStatementPreservesAllProperties(): void
    {
        // Given/When
        $attestationStatement = AttestationStatement::createAttCA('fmt', [
            'bar' => 'FOO',
        ], CertificateTrustPath::create(['key_id']));

        // Then
        static::assertSame('fmt', $attestationStatement->fmt);
        static::assertSame([
            'bar' => 'FOO',
        ], $attestationStatement->attStmt);
        static::assertTrue($attestationStatement->has('bar'));
        static::assertFalse($attestationStatement->has('foo'));
        static::assertSame('FOO', $attestationStatement->get('bar'));
        static::assertInstanceOf(CertificateTrustPath::class, $attestationStatement->trustPath);
        static::assertSame('attca', $attestationStatement->type);
    }

    #[Test]
    public function creatingSelfTypeAttestationStatementPreservesAllProperties(): void
    {
        // Given/When
        $attestationStatement = AttestationStatement::createSelf('fmt', [
            'bar' => 'FOO',
        ], CertificateTrustPath::create([]));

        // Then
        static::assertSame('fmt', $attestationStatement->fmt);
        static::assertSame([
            'bar' => 'FOO',
        ], $attestationStatement->attStmt);
        static::assertTrue($attestationStatement->has('bar'));
        static::assertFalse($attestationStatement->has('foo'));
        static::assertSame('FOO', $attestationStatement->get('bar'));
        static::assertInstanceOf(CertificateTrustPath::class, $attestationStatement->trustPath);
        static::assertSame('self', $attestationStatement->type);
    }
}
