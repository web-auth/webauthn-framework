<?php

declare(strict_types=1);

namespace Webauthn;

use function array_key_exists;
use Assert\Assertion;
use InvalidArgumentException;
use function is_string;
use JsonSerializable;
use ParagonIE\ConstantTime\Base64;
use Symfony\Component\Uid\AbstractUid;
use Symfony\Component\Uid\Uuid;

/**
 * @see https://www.w3.org/TR/webauthn/#sec-attested-credential-data
 */
class AttestedCredentialData implements JsonSerializable
{
    public function __construct(
        private AbstractUid $aaguid,
        private readonly string $credentialId,
        private readonly ?string $credentialPublicKey
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
        array_key_exists('aaguid', $json) || throw new InvalidArgumentException('Invalid input. "aaguid" is missing.');
        $aaguid = $json['aaguid'];
        is_string($aaguid) || throw new InvalidArgumentException(
            'Invalid input. "aaguid" shall be a string of 36 characters'
        );
        Assertion::length($aaguid, 36, 'Invalid input. "aaguid" shall be a string of 36 characters');
        $uuid = Uuid::fromString($json['aaguid']);

        array_key_exists('credentialId', $json) || throw new InvalidArgumentException(
            'Invalid input. "credentialId" is missing.'
        );
        $credentialId = $json['credentialId'];
        is_string($credentialId) || throw new InvalidArgumentException(
            'Invalid input. "credentialId" shall be a string'
        );
        $credentialId = Base64::decode($credentialId, true);

        $credentialPublicKey = null;
        if (isset($json['credentialPublicKey'])) {
            $credentialPublicKey = Base64::decode($json['credentialPublicKey'], true);
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
