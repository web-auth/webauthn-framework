<?php

declare(strict_types=1);

namespace Webauthn;

use JsonSerializable;
use ParagonIE\ConstantTime\Base64UrlSafe;
use Symfony\Component\Uid\Uuid;
use Webauthn\TrustPath\TrustPath;

/**
 * @see https://www.w3.org/TR/webauthn/#iface-pkcredential
 */
class PublicKeyCredentialSource implements JsonSerializable
{
    /**
     * @param string[] $transports
     * @param array<string, mixed>|null $otherUI
     */
    public function __construct(
        public string $publicKeyCredentialId,
        public string $type,
        public array $transports,
        public string $attestationType,
        public TrustPath $trustPath,
        public Uuid $aaguid,
        public string $credentialPublicKey,
        public string $userHandle,
        public int $counter,
        public ?array $otherUI = null,
        public ?bool $backupEligible = null,
        public ?bool $backupStatus = null,
        public ?bool $uvInitialized = null,
    ) {
    }

    /**
     * @param string[] $transports
     * @param array<string, mixed>|null $otherUI
     */
    public static function create(
        string $publicKeyCredentialId,
        string $type,
        array $transports,
        string $attestationType,
        TrustPath $trustPath,
        Uuid $aaguid,
        string $credentialPublicKey,
        string $userHandle,
        int $counter,
        ?array $otherUI = null,
        ?bool $backupEligible = null,
        ?bool $backupStatus = null,
        ?bool $uvInitialized = null,
    ): self {
        return new self(
            $publicKeyCredentialId,
            $type,
            $transports,
            $attestationType,
            $trustPath,
            $aaguid,
            $credentialPublicKey,
            $userHandle,
            $counter,
            $otherUI,
            $backupEligible,
            $backupStatus,
            $uvInitialized
        );
    }

    public function getPublicKeyCredentialDescriptor(): PublicKeyCredentialDescriptor
    {
        return PublicKeyCredentialDescriptor::create($this->type, $this->publicKeyCredentialId, $this->transports);
    }

    public function getAttestedCredentialData(): AttestedCredentialData
    {
        return AttestedCredentialData::create($this->aaguid, $this->publicKeyCredentialId, $this->credentialPublicKey);
    }

    /**
     * @return mixed[]
     */
    public function jsonSerialize(): array
    {
        return [
            'publicKeyCredentialId' => Base64UrlSafe::encodeUnpadded($this->publicKeyCredentialId),
            'type' => $this->type,
            'transports' => $this->transports,
            'attestationType' => $this->attestationType,
            'trustPath' => $this->trustPath,
            'aaguid' => $this->aaguid->__toString(),
            'credentialPublicKey' => Base64UrlSafe::encodeUnpadded($this->credentialPublicKey),
            'userHandle' => Base64UrlSafe::encodeUnpadded($this->userHandle),
            'counter' => $this->counter,
            'otherUI' => $this->otherUI,
            'backupEligible' => $this->backupEligible,
            'backupStatus' => $this->backupStatus,
            'uvInitialized' => $this->uvInitialized,
        ];
    }
}
