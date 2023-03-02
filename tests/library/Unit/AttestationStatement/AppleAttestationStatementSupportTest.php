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
    public function theAttestationStatementDoesNotContainTheRequiredCertificateList(): void
    {
        $this->expectException(AttestationStatementLoadingException::class);
        $this->expectExceptionMessage('The attestation statement value "x5c" is missing.');
        $support = new AppleAttestationStatementSupport();
        static::assertFalse($support->load([
            'fmt' => 'apple',
            'attStmt' => [
                'sig' => 'foo-bar',
            ],
        ]));
    }

    #[Test]
    public function theAttestationStatementContainsAnEmptyCertificateList(): void
    {
        $this->expectException(AttestationStatementLoadingException::class);
        $this->expectExceptionMessage(
            'The attestation statement value "x5c" must be a list with at least one certificate.'
        );
        $support = new AppleAttestationStatementSupport();

        static::assertSame('apple', $support->name());
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
