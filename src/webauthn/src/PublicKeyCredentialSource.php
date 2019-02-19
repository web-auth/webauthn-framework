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
     * @var string
     */
    private $type;

    /**
     * @var string[]
     */
    private $transports;

    /**
     * @var string
     */
    private $attestationObject;

    /**
     * @var string
     */
    private $aaguid;

    /**
     * @var string
     */
    private $credentialPublicKey;

    /**
     * @var string
     */
    private $userHandle;

    /**
     * @var int
     */
    private $counter;

    public function __construct(string $publicKeyCredentialId, string $type, array $transports, string $attestationObject, string $aaguid, string $credentialPublicKey, string $userHandle, int $counter)
    {
        $this->publicKeyCredentialId = $publicKeyCredentialId;
        $this->type = $type;
        $this->transports = $transports;
        $this->attestationObject = $attestationObject;
        $this->aaguid = $aaguid;
        $this->credentialPublicKey = $credentialPublicKey;
        $this->userHandle = $userHandle;
        $this->counter = $counter;
    }

    public function getPublicKeyCredentialId(): string
    {
        return $this->publicKeyCredentialId;
    }

    public function getPublicKeyCredentialDescriptor(): PublicKeyCredentialDescriptor
    {
        return new PublicKeyCredentialDescriptor(
            $this->type,
            $this->publicKeyCredentialId,
            $this->transports
        );
    }

    public function getAttestationObject(): string
    {
        return $this->attestationObject;
    }

    public function getAttestedCredentialData(): AttestedCredentialData
    {
        return new AttestedCredentialData(
            $this->aaguid,
            $this->publicKeyCredentialId,
            $this->credentialPublicKey
        );
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
