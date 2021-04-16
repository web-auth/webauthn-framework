<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2020 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

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
