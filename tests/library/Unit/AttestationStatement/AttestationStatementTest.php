<?php

declare(strict_types=1);

namespace Webauthn\Tests\Unit\AttestationStatement;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Webauthn\AttestationStatement\AttestationStatement;
use Webauthn\TrustPath\CertificateTrustPath;
use Webauthn\TrustPath\EcdaaKeyIdTrustPath;
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
        ], new EmptyTrustPath());
        static::assertSame('fmt', $attestationStatement->getFmt());
        static::assertSame([
            'bar' => 'FOO',
        ], $attestationStatement->getAttStmt());
        static::assertTrue($attestationStatement->has('bar'));
        static::assertFalse($attestationStatement->has('foo'));
        static::assertSame('FOO', $attestationStatement->get('bar'));
        static::assertInstanceOf(EmptyTrustPath::class, $attestationStatement->getTrustPath());
        static::assertSame('none', $attestationStatement->getType());
    }

    #[Test]
    public function anAttestationStatementOfEcdaaTypeReturnsTheExpectedProperties(): void
    {
        $attestationStatement = AttestationStatement::createEcdaa('fmt', [
            'bar' => 'FOO',
        ], new EcdaaKeyIdTrustPath('key_id'));
        static::assertSame('fmt', $attestationStatement->getFmt());
        static::assertSame([
            'bar' => 'FOO',
        ], $attestationStatement->getAttStmt());
        static::assertTrue($attestationStatement->has('bar'));
        static::assertFalse($attestationStatement->has('foo'));
        static::assertSame('FOO', $attestationStatement->get('bar'));
        static::assertInstanceOf(EcdaaKeyIdTrustPath::class, $attestationStatement->getTrustPath());
        static::assertSame('ecdaa', $attestationStatement->getType());
    }

    #[Test]
    public function anAttestationStatementOfBasicTypeReturnsTheExpectedProperties(): void
    {
        $attestationStatement = AttestationStatement::createBasic('fmt', [
            'bar' => 'FOO',
        ], new CertificateTrustPath(['key_id']));
        static::assertSame('fmt', $attestationStatement->getFmt());
        static::assertSame([
            'bar' => 'FOO',
        ], $attestationStatement->getAttStmt());
        static::assertTrue($attestationStatement->has('bar'));
        static::assertFalse($attestationStatement->has('foo'));
        static::assertSame('FOO', $attestationStatement->get('bar'));
        static::assertInstanceOf(CertificateTrustPath::class, $attestationStatement->getTrustPath());
        static::assertSame('basic', $attestationStatement->getType());
    }

    #[Test]
    public function anAttestationStatementOfAttCATypeReturnsTheExpectedProperties(): void
    {
        $attestationStatement = AttestationStatement::createAttCA('fmt', [
            'bar' => 'FOO',
        ], new CertificateTrustPath(['key_id']));
        static::assertSame('fmt', $attestationStatement->getFmt());
        static::assertSame([
            'bar' => 'FOO',
        ], $attestationStatement->getAttStmt());
        static::assertTrue($attestationStatement->has('bar'));
        static::assertFalse($attestationStatement->has('foo'));
        static::assertSame('FOO', $attestationStatement->get('bar'));
        static::assertInstanceOf(CertificateTrustPath::class, $attestationStatement->getTrustPath());
        static::assertSame('attca', $attestationStatement->getType());
    }

    #[Test]
    public function anAttestationStatementOfSelfTypeReturnsTheExpectedProperties(): void
    {
        $attestationStatement = AttestationStatement::createSelf('fmt', [
            'bar' => 'FOO',
        ], new CertificateTrustPath([]));
        static::assertSame('fmt', $attestationStatement->getFmt());
        static::assertSame([
            'bar' => 'FOO',
        ], $attestationStatement->getAttStmt());
        static::assertTrue($attestationStatement->has('bar'));
        static::assertFalse($attestationStatement->has('foo'));
        static::assertSame('FOO', $attestationStatement->get('bar'));
        static::assertInstanceOf(CertificateTrustPath::class, $attestationStatement->getTrustPath());
        static::assertSame('self', $attestationStatement->getType());
    }
}
