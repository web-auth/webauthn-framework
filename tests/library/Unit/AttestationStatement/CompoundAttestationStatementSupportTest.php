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
    public function supportReturnsCorrectName(): void
    {
        // Given
        $manager = new AttestationStatementSupportManager([]);
        $support = new CompoundAttestationStatementSupport();
        $support->setAttestationStatementSupportManager($manager);

        // When/Then
        static::assertSame('compound', $support->name());
    }

    #[Test]
    public function loadingCompoundAttestationWithMultipleNestedAttestationsSucceeds(): void
    {
        // Given
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

        // When
        $result = $support->load($attestation);

        // Then
        static::assertSame('compound', $result->fmt);
        static::assertInstanceOf(EmptyTrustPath::class, $result->trustPath);
        static::assertCount(2, $result->attStmt);
    }

    #[Test]
    public function loadingCompoundAttestationWithNonArrayAttestationsThrowsException(): void
    {
        // Then
        $this->expectException(AttestationStatementLoadingException::class);
        $this->expectExceptionMessage('Invalid attestation object');

        // Given
        $manager = new AttestationStatementSupportManager([]);
        $support = new CompoundAttestationStatementSupport();
        $support->setAttestationStatementSupportManager($manager);

        $attestation = [
            'fmt' => 'compound',
            'attStmt' => 'not-an-array',
        ];

        // When
        $support->load($attestation);
    }

    #[Test]
    public function validatingCompoundAttestationWithEmptyAttestationsThrowsException(): void
    {
        // Then
        $this->expectException(AttestationStatementVerificationException::class);
        $this->expectExceptionMessage('Compound attestation must contain at least two attestations.');

        // Given
        $manager = new AttestationStatementSupportManager([]);
        $support = new CompoundAttestationStatementSupport();
        $support->setAttestationStatementSupportManager($manager);

        $attestation = [
            'fmt' => 'compound',
            'attStmt' => [],
        ];

        $attestationStatement = $support->load($attestation);
        $authenticatorData = AuthenticatorData::create('', '', '', 0);

        // When
        $support->isValid('FOO', $attestationStatement, $authenticatorData);
    }

    #[Test]
    public function loadingCompoundAttestationWithNestedAttestationMissingFmtThrowsException(): void
    {
        // Then
        $this->expectException(InvalidDataException::class);
        $this->expectExceptionMessage('Invalid attestation object');

        // Given
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

        // When
        $support->load($attestation);
    }

    #[Test]
    public function loadingCompoundAttestationWithNestedAttestationMissingAttStmtThrowsException(): void
    {
        // Then
        $this->expectException(InvalidDataException::class);
        $this->expectExceptionMessage('Invalid attestation object');

        // Given
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

        // When
        $support->load($attestation);
    }

    #[Test]
    public function loadingCompoundAttestationWithUnsupportedNestedFormatThrowsException(): void
    {
        // Then
        $this->expectException(AttestationStatementLoadingException::class);
        $this->expectExceptionMessage('Unsupported attestation format "unsupported-format" at index 0.');

        // Given
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

        // When
        $support->load($attestation);
    }

    #[Test]
    public function validatingCompoundAttestationWithValidNestedAttestationsSucceeds(): void
    {
        // Given
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

        // When
        $isValid = $support->isValid('FOO', $attestationStatement, $authenticatorData);

        // Then
        static::assertTrue($isValid);
    }
}
