<?php

declare(strict_types=1);

namespace Webauthn\AttestationStatement;

use Webauthn\AuthenticatorData;

interface AttestationStatementSupport
{
    public function name(): string;

    public function load(array $attestation): AttestationStatement;

    public function isValid(string $clientDataJSONHash, AttestationStatement $attestationStatement, AuthenticatorData $authenticatorData): bool;
}
