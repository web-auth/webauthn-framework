<?php

declare(strict_types=1);

namespace Webauthn\AttestationStatement;

use Webauthn\AuthenticatorData;
use Webauthn\MetadataService\Statement\MetadataStatement;

class AttestationObject
{
    private ?MetadataStatement $metadataStatement = null;

    public function __construct(
        private readonly string $rawAttestationObject,
        private AttestationStatement $attStmt,
        private readonly AuthenticatorData $authData
    ) {
    }

    public function getRawAttestationObject(): string
    {
        return $this->rawAttestationObject;
    }

    public function getAttStmt(): AttestationStatement
    {
        return $this->attStmt;
    }

    public function setAttStmt(AttestationStatement $attStmt): void
    {
        $this->attStmt = $attStmt;
    }

    public function getAuthData(): AuthenticatorData
    {
        return $this->authData;
    }

    public function getMetadataStatement(): ?MetadataStatement
    {
        return $this->metadataStatement;
    }

    public function setMetadataStatement(MetadataStatement $metadataStatement): self
    {
        $this->metadataStatement = $metadataStatement;

        return $this;
    }
}
