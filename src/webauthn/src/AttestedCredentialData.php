<?php

declare(strict_types=1);

namespace Webauthn;

use Assert\Assertion;
use JsonSerializable;
use Ramsey\Uuid\Uuid;
use Ramsey\Uuid\UuidInterface;

/**
 * @see https://www.w3.org/TR/webauthn/#sec-attested-credential-data
 */
class AttestedCredentialData implements JsonSerializable
{
    public function __construct(
        private UuidInterface $aaguid,
        private string $credentialId,
        private ?string $credentialPublicKey
    ) {
    }

    public function getAaguid(): UuidInterface
    {
        return $this->aaguid;
    }

    public function setAaguid(UuidInterface $aaguid): void
    {
        $this->aaguid = $aaguid;
    }

    public function getCredentialId(): string
    {
        return $this->credentialId;
    }

    public function getCredentialPublicKey(): ?string
    {
        return $this->credentialPublicKey;
    }

    /**
     * @param mixed[] $json
     */
    public static function createFromArray(array $json): self
    {
        Assertion::keyExists($json, 'aaguid', 'Invalid input. "aaguid" is missing.');
        Assertion::keyExists($json, 'credentialId', 'Invalid input. "credentialId" is missing.');
        switch (true) {
            case mb_strlen($json['aaguid'], '8bit') === 36:
                $uuid = Uuid::fromString($json['aaguid']);
                break;
            default: // Kept for compatibility with old format
                $decoded = base64_decode($json['aaguid'], true);
                Assertion::string($decoded, 'Unable to get the AAGUID');
                $uuid = Uuid::fromBytes($decoded);
        }
        $credentialId = base64_decode($json['credentialId'], true);
        Assertion::string($credentialId, 'Unable to get the public key ID');

        $credentialPublicKey = null;
        if (isset($json['credentialPublicKey'])) {
            $credentialPublicKey = base64_decode($json['credentialPublicKey'], true);
            Assertion::string($credentialPublicKey, 'Unable to get the public key');
        }

        return new self($uuid, $credentialId, $credentialPublicKey);
    }

    /**
     * @return mixed[]
     */
    public function jsonSerialize(): array
    {
        $result = [
            'aaguid' => $this->aaguid->toString(),
            'credentialId' => base64_encode($this->credentialId),
        ];
        if ($this->credentialPublicKey !== null) {
            $result['credentialPublicKey'] = base64_encode($this->credentialPublicKey);
        }

        return $result;
    }
}
