<?php

declare(strict_types=1);

namespace Webauthn\Tests\Unit\AttestationStatement;

use PHPUnit\Framework\TestCase;
use Webauthn\AttestationStatement\AndroidKeyAttestationStatementSupport;
use Webauthn\Exception\AttestationStatementLoadingException;

/**
 * @internal
 */
final class AndroidKeyAttestationStatementSupportTest extends TestCase
{
    /**
     * @test
     */
    public function theAttestationStatementDoesNotContainTheRequiredSignature(): void
    {
        $this->expectException(AttestationStatementLoadingException::class);
        $this->expectExceptionMessage('The attestation statement value "sig" is missing.');
        $support = new AndroidKeyAttestationStatementSupport();

        static::assertSame('android-key', $support->name());
        static::assertFalse($support->load([
            'fmt' => 'android-key',
            'attStmt' => [],
        ]));
    }

    /**
     * @test
     */
    public function theAttestationStatementDoesNotContainTheRequiredCertificateList(): void
    {
        $this->expectException(AttestationStatementLoadingException::class);
        $this->expectExceptionMessage('The attestation statement value "x5c" is missing.');
        $support = new AndroidKeyAttestationStatementSupport();
        static::assertFalse($support->load([
            'fmt' => 'android-key',
            'attStmt' => [
                'sig' => 'foo-bar',
            ],
        ]));
    }

    /**
     * @test
     */
    public function theAttestationStatementDoesNotContainTheRequiredAlgorithmParameter(): void
    {
        $this->expectException(AttestationStatementLoadingException::class);
        $this->expectExceptionMessage('The attestation statement value "alg" is missing.');
        $support = new AndroidKeyAttestationStatementSupport();
        static::assertFalse($support->load([
            'fmt' => 'android-key',
            'attStmt' => [
                'sig' => 'foo-bar',
                'x5c' => [],
            ],
        ]));
    }

    /**
     * @test
     */
    public function theAttestationStatementContainsAnEmptyCertificateList(): void
    {
        $this->expectException(AttestationStatementLoadingException::class);
        $this->expectExceptionMessage(
            'The attestation statement value "x5c" must be a list with at least one certificate.'
        );
        $support = new AndroidKeyAttestationStatementSupport();

        static::assertSame('android-key', $support->name());
        static::assertFalse($support->load([
            'fmt' => 'android-key',
            'attStmt' => [
                'sig' => 'foo-bar',
                'x5c' => [],
                'alg' => -7,
            ],
        ]));
    }
}
