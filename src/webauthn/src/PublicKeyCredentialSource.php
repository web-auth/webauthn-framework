<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Webauthn;

use Webauthn\AttestationStatement\AttestationStatement;

/**
 * @see https://www.w3.org/TR/webauthn/#iface-pkcredential
 */
class PublicKeyCredentialSource
{
    /**
     * @var string
     */
    private $publicKeyCredentialId;

    /**
     * @var PublicKeyCredentialDescriptor
     */
    private $publicKeyCredentialDescriptor;

    /**
     * @var AttestationStatement|null
     */
    private $attestationStatement;

    /**
     * @var AttestedCredentialData
     */
    private $attestedCredentialData;

    /**
     * @var string
     */
    private $userHandle;

    /**
     * @var int
     */
    private $counter;

    public function __construct(string $publicKeyCredentialId, PublicKeyCredentialDescriptor $publicKeyCredentialDescriptor, ?AttestationStatement $attestationStatement, AttestedCredentialData $attestedCredentialData, string $userHandle, int $counter)
    {
        $this->publicKeyCredentialId = $publicKeyCredentialId;
        $this->publicKeyCredentialDescriptor = $publicKeyCredentialDescriptor;
        $this->attestationStatement = $attestationStatement;
        $this->attestedCredentialData = $attestedCredentialData;
        $this->userHandle = $userHandle;
        $this->counter = $counter;
    }

    public function getPublicKeyCredentialId(): string
    {
        return $this->publicKeyCredentialId;
    }

    public function getPublicKeyCredentialDescriptor(): PublicKeyCredentialDescriptor
    {
        return $this->publicKeyCredentialDescriptor;
    }

    public function getAttestationStatement(): ?AttestationStatement
    {
        return $this->attestationStatement;
    }

    public function getAttestedCredentialData(): AttestedCredentialData
    {
        return $this->attestedCredentialData;
    }

    public function getUserHandle(): string
    {
        return $this->userHandle;
    }

    public function getCounter(): int
    {
        return $this->counter;
    }

    public function setCounter(int $counter): void
    {
        $this->counter = $counter;
    }
}
