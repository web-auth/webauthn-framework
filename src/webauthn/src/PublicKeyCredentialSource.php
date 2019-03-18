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

use Assert\Assertion;
use Webauthn\TrustPath\TrustPath;

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
    private $attestationType;

    /**
     * @var TrustPath
     */
    private $trustPath;

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

    public function __construct(string $publicKeyCredentialId, string $type, array $transports, string $attestationType, TrustPath $trustPath, string $aaguid, string $credentialPublicKey, string $userHandle, int $counter)
    {
        $this->publicKeyCredentialId = $publicKeyCredentialId;
        $this->type = $type;
        $this->transports = $transports;
        $this->aaguid = $aaguid;
        $this->credentialPublicKey = $credentialPublicKey;
        $this->userHandle = $userHandle;
        $this->counter = $counter;
        $this->attestationType = $attestationType;
        $this->trustPath = $trustPath;
    }

    public static function createFromPublicKeyCredential(PublicKeyCredential $publicKeyCredential, string $userHandle): self
    {
        $response = $publicKeyCredential->getResponse();
        Assertion::isInstanceOf($response, AuthenticatorAttestationResponse::class, 'This method is only available with public key credential containing an authenticator attestation response.');
        $publicKeyCredentialDescriptor = $publicKeyCredential->getPublicKeyCredentialDescriptor();
        $attestationStatement = $response->getAttestationObject()->getAttStmt();
        $authenticatorData = $response->getAttestationObject()->getAuthData();
        $attestedCredentialData = $authenticatorData->getAttestedCredentialData();
        Assertion::notNull($attestedCredentialData, 'No attested credential data available');

        return new self(
            $publicKeyCredentialDescriptor->getId(),
            $publicKeyCredentialDescriptor->getType(),
            $publicKeyCredentialDescriptor->getTransports(),
            $attestationStatement->getType(),
            $attestationStatement->getTrustPath(),
            $attestedCredentialData->getAaguid(),
            $attestedCredentialData->getCredentialPublicKey(),
            $userHandle,
            $authenticatorData->getSignCount()
        );
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

    public function getAttestationType(): string
    {
        return $this->attestationType;
    }

    public function getTrustPath(): TrustPath
    {
        return $this->trustPath;
    }

    public function getAttestedCredentialData(): AttestedCredentialData
    {
        return new AttestedCredentialData(
            $this->aaguid,
            $this->publicKeyCredentialId,
            $this->credentialPublicKey
        );
    }

    public function getType(): string
    {
        return $this->type;
    }

    /**
     * @return string[]
     */
    public function getTransports(): array
    {
        return $this->transports;
    }

    public function getAaguid(): string
    {
        return $this->aaguid;
    }

    public function getCredentialPublicKey(): string
    {
        return $this->credentialPublicKey;
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
