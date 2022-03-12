<?php

declare(strict_types=1);

namespace Webauthn\AttestationStatement;

use Webauthn\AuthenticatorData;
use Webauthn\MetadataService\MetadataStatement;

class AttestationObject
{
    private ?MetadataStatement $metadataStatement;

    
    public function __construct(private string $rawAttestationObject, private AttestationStatement $attStmt, private AuthenticatorData $authData)
    {
        $this->metadataStatement = null;
    }

    
    public static function create(string $rawAttestationObject, AttestationStatement $attStmt, AuthenticatorData $authData): self
    {
        return new self($rawAttestationObject, $attStmt, $authData);
    }

    
    public function getRawAttestationObject(): string
    {
        return $this->rawAttestationObject;
    }

    
    public function getAttStmt(): AttestationStatement
    {
        return $this->attStmt;
    }

    public function setAttStmt(AttestationStatement $attStmt): self
    {
        $this->attStmt = $attStmt;

        return $this;
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
