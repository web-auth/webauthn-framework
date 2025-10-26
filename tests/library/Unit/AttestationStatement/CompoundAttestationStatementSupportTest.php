<?php

declare(strict_types=1);

namespace Webauthn\Tests\Unit\AttestationStatement;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AttestationStatement\CompoundAttestationStatementSupport;
use Webauthn\AttestationStatement\NoneAttestationStatementSupport;
use Webauthn\AuthenticatorData;
use Webauthn\Exception\AttestationStatementLoadingException;
use Webauthn\Exception\AttestationStatementVerificationException;
use Webauthn\Exception\InvalidDataException;
use Webauthn\TrustPath\EmptyTrustPath;

/**
 * @internal
 */
final class CompoundAttestationStatementSupportTest extends TestCase
{
    #[Test]
    public function theSupportReturnsCorrectName(): void
    {
        $manager = new AttestationStatementSupportManager([]);
        $support = new CompoundAttestationStatementSupport();
        $support->setAttestationStatementSupportManager($manager);

        static::assertSame('compound', $support->name());
    }

    #[Test]
    public function itLoadsCompoundAttestationWithMultipleNestedAttestations(): void
    {
        $manager = new AttestationStatementSupportManager([]);
        $support = new CompoundAttestationStatementSupport();
        $support->setAttestationStatementSupportManager($manager);

        $attestation = [
            'fmt' => 'compound',
            'attStmt' => [
                [
                    'fmt' => 'none',
                    'attStmt' => [],
                ],
                [
                    'fmt' => 'none',
                    'attStmt' => [],
                ],
            ],
        ];

        $result = $support->load($attestation);

        static::assertSame('compound', $result->fmt);
        static::assertInstanceOf(EmptyTrustPath::class, $result->trustPath);
        static::assertCount(2, $result->attStmt);
    }

    #[Test]
    public function itThrowsExceptionWhenAttestationsIsNotAnArray(): void
    {
        $manager = new AttestationStatementSupportManager([]);
        $support = new CompoundAttestationStatementSupport();
        $support->setAttestationStatementSupportManager($manager);

        $attestation = [
            'fmt' => 'compound',
            'attStmt' => 'not-an-array',
        ];

        $this->expectException(AttestationStatementLoadingException::class);
        $this->expectExceptionMessage('Invalid attestation object');

        $support->load($attestation);
    }

    #[Test]
    public function itThrowsExceptionWhenAttestationsIsEmpty(): void
    {
        $manager = new AttestationStatementSupportManager([]);
        $support = new CompoundAttestationStatementSupport();
        $support->setAttestationStatementSupportManager($manager);

        $attestation = [
            'fmt' => 'compound',
            'attStmt' => [],
        ];

        $this->expectException(AttestationStatementVerificationException::class);
        $this->expectExceptionMessage('Compound attestation must contain at least two attestations.');

        $attestationStatement = $support->load($attestation);
        $authenticatorData = AuthenticatorData::create('', '', '', 0);
        $support->isValid('FOO', $attestationStatement, $authenticatorData);
    }

    #[Test]
    public function itThrowsExceptionWhenNestedAttestationMissingFmt(): void
    {
        $manager = new AttestationStatementSupportManager([]);
        $support = new CompoundAttestationStatementSupport();
        $support->setAttestationStatementSupportManager($manager);

        $attestation = [
            'fmt' => 'compound',
            'attStmt' => [
                [
                    'attStmt' => [],
                ],
                [
                    'fmt' => 'none',
                    'attStmt' => [],
                ],
            ],
        ];

        $this->expectException(InvalidDataException::class);
        $this->expectExceptionMessage('Invalid attestation object');

        $support->load($attestation);
    }

    #[Test]
    public function itThrowsExceptionWhenNestedAttestationMissingAttStmt(): void
    {
        $manager = new AttestationStatementSupportManager([]);
        $support = new CompoundAttestationStatementSupport();
        $support->setAttestationStatementSupportManager($manager);

        $attestation = [
            'fmt' => 'compound',
            'attStmt' => [
                [
                    'fmt' => 'none',
                ],
                [
                    'fmt' => 'none',
                    'attStmt' => [],
                ],
            ],
        ];

        $this->expectException(InvalidDataException::class);
        $this->expectExceptionMessage('Invalid attestation object');

        $support->load($attestation);
    }

    #[Test]
    public function itThrowsExceptionWhenNestedAttestationFormatIsUnsupported(): void
    {
        $manager = new AttestationStatementSupportManager([]);
        $support = new CompoundAttestationStatementSupport();
        $support->setAttestationStatementSupportManager($manager);

        $attestation = [
            'fmt' => 'compound',
            'attStmt' => [
                [
                    'fmt' => 'unsupported-format',
                    'attStmt' => [],
                ],
                [
                    'fmt' => 'none',
                    'attStmt' => [],
                ],
            ],
        ];

        $this->expectException(AttestationStatementLoadingException::class);
        $this->expectExceptionMessage('Unsupported attestation format "unsupported-format" at index 0.');

        $support->load($attestation);
    }

    #[Test]
    public function itValidatesCompoundAttestationSuccessfully(): void
    {
        $manager = new AttestationStatementSupportManager([new NoneAttestationStatementSupport()]);
        $support = new CompoundAttestationStatementSupport();
        $support->setAttestationStatementSupportManager($manager);

        // Load a compound attestation with two 'none' attestations
        $attestation = [
            'fmt' => 'compound',
            'attStmt' => [
                [
                    'fmt' => 'none',
                    'attStmt' => [],
                ],
                [
                    'fmt' => 'none',
                    'attStmt' => [],
                ],
            ],
        ];

        $attestationStatement = $support->load($attestation);
        $authenticatorData = AuthenticatorData::create('', '', '', 0);

        $isValid = $support->isValid('FOO', $attestationStatement, $authenticatorData);

        static::assertTrue($isValid);
    }
}
