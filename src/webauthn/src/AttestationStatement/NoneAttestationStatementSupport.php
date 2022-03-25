<?php

declare(strict_types=1);

namespace Webauthn\AttestationStatement;

use Assert\Assertion;
use function count;
use Webauthn\AuthenticatorData;
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
        Assertion::noContent($attestation['attStmt'], 'Invalid attestation object');

        return AttestationStatement::createNone($attestation['fmt'], $attestation['attStmt'], new EmptyTrustPath());
    }

    public function isValid(
        string $clientDataJSONHash,
        AttestationStatement $attestationStatement,
        AuthenticatorData $authenticatorData
    ): bool {
        return count($attestationStatement->getAttStmt()) === 0;
    }
}
