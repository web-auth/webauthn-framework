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
    public function anAttestationStatementOfNoneTypeReturnsTheExpectedProperties(): void
    {
        $attestationStatement = AttestationStatement::createNone('fmt', [
            'bar' => 'FOO',
        ], EmptyTrustPath::create());
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
    public function anAttestationStatementOfBasicTypeReturnsTheExpectedProperties(): void
    {
        $attestationStatement = AttestationStatement::createBasic('fmt', [
            'bar' => 'FOO',
        ], CertificateTrustPath::create(['key_id']));
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
    public function anAttestationStatementOfAttCATypeReturnsTheExpectedProperties(): void
    {
        $attestationStatement = AttestationStatement::createAttCA('fmt', [
            'bar' => 'FOO',
        ], CertificateTrustPath::create(['key_id']));
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
    public function anAttestationStatementOfSelfTypeReturnsTheExpectedProperties(): void
    {
        $attestationStatement = AttestationStatement::createSelf('fmt', [
            'bar' => 'FOO',
        ], CertificateTrustPath::create([]));
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
