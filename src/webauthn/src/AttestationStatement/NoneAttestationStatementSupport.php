<?php

declare(strict_types=1);

namespace Webauthn\AttestationStatement;

use function count;
use function is_array;
use function is_string;
use Webauthn\AuthenticatorData;
use Webauthn\Exception\AttestationStatementLoadingException;
use Webauthn\TrustPath\EmptyTrustPath;

final class NoneAttestationStatementSupport implements AttestationStatementSupport
{
    public static function create(): self
    {
        return new self();
    }

    public function name(): string
    {
        return 'none';
    }

    /**
     * @param array<string, mixed> $attestation
     */
    public function load(array $attestation): AttestationStatement
    {
        $format = $attestation['fmt'] ?? null;
        $attestationStatement = $attestation['attStmt'] ?? [];

        (is_string($format) && $format !== '') || throw AttestationStatementLoadingException::create(
            $attestation,
            'Invalid attestation object'
        );
        (is_array(
            $attestationStatement
        ) && $attestationStatement === []) || throw AttestationStatementLoadingException::create(
            $attestation,
            'Invalid attestation object'
        );

        return AttestationStatement::createNone($format, $attestationStatement, EmptyTrustPath::create());
    }

    public function isValid(
        string $clientDataJSONHash,
        AttestationStatement $attestationStatement,
        AuthenticatorData $authenticatorData
    ): bool {
        return count($attestationStatement->getAttStmt()) === 0;
    }
}
