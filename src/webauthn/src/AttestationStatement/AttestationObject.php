<?php

declare(strict_types=1);

namespace Webauthn\AttestationStatement;

use JetBrains\PhpStorm\Pure;
use Webauthn\AuthenticatorData;
use Webauthn\MetadataService\MetadataStatement;

class AttestationObject
{
    private ?MetadataStatement $metadataStatement;

    #[Pure]
    public function __construct(private string $rawAttestationObject, private AttestationStatement $attStmt, private AuthenticatorData $authData)
    {
        $this->metadataStatement = null;
    }

    #[Pure]
    public static function create(string $rawAttestationObject, AttestationStatement $attStmt, AuthenticatorData $authData): self
    {
        return new self($rawAttestationObject, $attStmt, $authData);
    }

    #[Pure]
    public function getRawAttestationObject(): string
    {
        return $this->rawAttestationObject;
    }

    #[Pure]
    public function getAttStmt(): AttestationStatement
    {
        return $this->attStmt;
    }

    public function setAttStmt(AttestationStatement $attStmt): self
    {
        $this->attStmt = $attStmt;

        return $this;
    }

    #[Pure]
    public function getAuthData(): AuthenticatorData
    {
        return $this->authData;
    }

    #[Pure]
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
