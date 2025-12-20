<?php

declare(strict_types=1);

namespace Webauthn\Tests\Unit\AttestationStatement;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Webauthn\AttestationStatement\AppleAttestationStatementSupport;
use Webauthn\Exception\AttestationStatementLoadingException;

/**
 * @internal
 */
final class AppleAttestationStatementSupportTest extends TestCase
{
    #[Test]
    public function loadingAttestationWithoutCertificateListThrowsException(): void
    {
        // Then
        $this->expectException(AttestationStatementLoadingException::class);
        $this->expectExceptionMessage('The attestation statement value "x5c" is missing.');

        // Given
        $support = new AppleAttestationStatementSupport();

        // When
        static::assertFalse($support->load([
            'fmt' => 'apple',
            'attStmt' => [
                'sig' => 'foo-bar',
            ],
        ]));
    }

    #[Test]
    public function loadingAttestationWithEmptyCertificateListThrowsException(): void
    {
        // Then
        $this->expectException(AttestationStatementLoadingException::class);
        $this->expectExceptionMessage(
            'The attestation statement value "x5c" must be a list with at least one certificate.'
        );

        // Given
        $support = new AppleAttestationStatementSupport();

        static::assertSame('apple', $support->name());

        // When
        static::assertFalse($support->load([
            'fmt' => 'apple',
            'attStmt' => [
                'sig' => 'foo-bar',
                'x5c' => [],
                'alg' => -7,
            ],
        ]));
    }
}
