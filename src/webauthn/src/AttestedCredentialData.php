<?php

declare(strict_types=1);

namespace Webauthn;

use Assert\Assertion;
use JsonSerializable;
use Symfony\Component\Uid\AbstractUid;
use Symfony\Component\Uid\Uuid;

/**
 * @see https://www.w3.org/TR/webauthn/#sec-attested-credential-data
 */
class AttestedCredentialData implements JsonSerializable
{
    public function __construct(
        private AbstractUid $aaguid,
        private string $credentialId,
        private ?string $credentialPublicKey
    ) {
    }

    public function getAaguid(): AbstractUid
    {
        return $this->aaguid;
    }

    public function setAaguid(AbstractUid $aaguid): void
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
        $aaguid = $json['aaguid'];
        Assertion::string($aaguid, 'Invalid input. "aaguid" shall be a string of 36 characters');
        Assertion::length($aaguid, 36, 'Invalid input. "aaguid" shall be a string of 36 characters');
        $uuid = Uuid::fromString($json['aaguid']);

        Assertion::keyExists($json, 'credentialId', 'Invalid input. "credentialId" is missing.');
        $credentialId = $json['credentialId'];
        Assertion::string($credentialId, 'Invalid input. "credentialId" shall be a string');
        $credentialId = base64_decode($credentialId, true);
        Assertion::string($credentialId, 'Invalid input. Unable to get the public key ID');

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
            'aaguid' => $this->aaguid->__toString(),
            'credentialId' => base64_encode($this->credentialId),
        ];
        if ($this->credentialPublicKey !== null) {
            $result['credentialPublicKey'] = base64_encode($this->credentialPublicKey);
        }

        return $result;
    }
}
