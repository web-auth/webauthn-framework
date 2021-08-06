<?php

declare(strict_types=1);

namespace Webauthn\AttestationStatement;

use Assert\Assertion;
use function count;
use JetBrains\PhpStorm\Pure;
use Webauthn\AuthenticatorData;
use Webauthn\TrustPath\EmptyTrustPath;

final class NoneAttestationStatementSupport implements AttestationStatementSupport
{
    #[Pure]
    public static function create(): self
    {
        return new self();
    }

    #[Pure]
    public function name(): string
    {
        return 'none';
    }

    public function load(array $attestation): AttestationStatement
    {
        Assertion::noContent($attestation['attStmt'], 'Invalid attestation object');

        return AttestationStatement::createNone($attestation['fmt'], $attestation['attStmt'], EmptyTrustPath::create());
    }

    #[Pure]
    public function isValid(string $clientDataJSONHash, AttestationStatement $attestationStatement, AuthenticatorData $authenticatorData): bool
    {
        return 0 === count($attestationStatement->getAttStmt());
    }
}
