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
use Webauthn\TrustPath\CertificateTrustPath;
use Webauthn\TrustPath\EcdaaKeyIdTrustPath;
use Webauthn\TrustPath\EmptyTrustPath;

/**
 * @group unit
 * @group Fido2
 *
 * @covers \Webauthn\AttestationStatement\AttestationStatement
 */
class AttestationStatementTest extends TestCase
{
    /**
     * @test
     */
    public function anAttestationStatementOfNoneTypeReturnsTheExpectedProperties(): void
    {
        $attestationStatement = AttestationStatement::createNone('fmt', ['bar' => 'FOO'], new EmptyTrustPath());
        static::assertEquals('fmt', $attestationStatement->getFmt());
        static::assertEquals(['bar' => 'FOO'], $attestationStatement->getAttStmt());
        static::assertTrue($attestationStatement->has('bar'));
        static::assertFalse($attestationStatement->has('foo'));
        static::assertEquals('FOO', $attestationStatement->get('bar'));
        static::assertInstanceOf(EmptyTrustPath::class, $attestationStatement->getTrustPath());
        static::assertEquals('none', $attestationStatement->getType());
    }

    /**
     * @test
     */
    public function anAttestationStatementOfEcdaaTypeReturnsTheExpectedProperties(): void
    {
        $attestationStatement = AttestationStatement::createEcdaa('fmt', ['bar' => 'FOO'], new EcdaaKeyIdTrustPath('key_id'));
        static::assertEquals('fmt', $attestationStatement->getFmt());
        static::assertEquals(['bar' => 'FOO'], $attestationStatement->getAttStmt());
        static::assertTrue($attestationStatement->has('bar'));
        static::assertFalse($attestationStatement->has('foo'));
        static::assertEquals('FOO', $attestationStatement->get('bar'));
        static::assertInstanceOf(EcdaaKeyIdTrustPath::class, $attestationStatement->getTrustPath());
        static::assertEquals('ecdaa', $attestationStatement->getType());
    }

    /**
     * @test
     */
    public function anAttestationStatementOfBasicTypeReturnsTheExpectedProperties(): void
    {
        $attestationStatement = AttestationStatement::createBasic('fmt', ['bar' => 'FOO'], new CertificateTrustPath(['key_id']));
        static::assertEquals('fmt', $attestationStatement->getFmt());
        static::assertEquals(['bar' => 'FOO'], $attestationStatement->getAttStmt());
        static::assertTrue($attestationStatement->has('bar'));
        static::assertFalse($attestationStatement->has('foo'));
        static::assertEquals('FOO', $attestationStatement->get('bar'));
        static::assertInstanceOf(CertificateTrustPath::class, $attestationStatement->getTrustPath());
        static::assertEquals('basic', $attestationStatement->getType());
    }

    /**
     * @test
     */
    public function anAttestationStatementOfAttCATypeReturnsTheExpectedProperties(): void
    {
        $attestationStatement = AttestationStatement::createAttCA('fmt', ['bar' => 'FOO'], new CertificateTrustPath(['key_id']));
        static::assertEquals('fmt', $attestationStatement->getFmt());
        static::assertEquals(['bar' => 'FOO'], $attestationStatement->getAttStmt());
        static::assertTrue($attestationStatement->has('bar'));
        static::assertFalse($attestationStatement->has('foo'));
        static::assertEquals('FOO', $attestationStatement->get('bar'));
        static::assertInstanceOf(CertificateTrustPath::class, $attestationStatement->getTrustPath());
        static::assertEquals('attca', $attestationStatement->getType());
    }

    /**
     * @test
     */
    public function anAttestationStatementOfSelfTypeReturnsTheExpectedProperties(): void
    {
        $attestationStatement = AttestationStatement::createSelf('fmt', ['bar' => 'FOO'], new CertificateTrustPath([]));
        static::assertEquals('fmt', $attestationStatement->getFmt());
        static::assertEquals(['bar' => 'FOO'], $attestationStatement->getAttStmt());
        static::assertTrue($attestationStatement->has('bar'));
        static::assertFalse($attestationStatement->has('foo'));
        static::assertEquals('FOO', $attestationStatement->get('bar'));
        static::assertInstanceOf(CertificateTrustPath::class, $attestationStatement->getTrustPath());
        static::assertEquals('self', $attestationStatement->getType());
    }
}
