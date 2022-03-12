<?php

declare(strict_types=1);

namespace Webauthn;

use Assert\Assertion;
use JetBrains\PhpStorm\ArrayShape;
use JsonSerializable;
use Ramsey\Uuid\Uuid;
use Ramsey\Uuid\UuidInterface;
use function Safe\base64_decode;

/**
 * @see https://www.w3.org/TR/webauthn/#sec-attested-credential-data
 */
class AttestedCredentialData implements JsonSerializable
{
    
    public function __construct(private UuidInterface $aaguid, private string $credentialId, private ?string $credentialPublicKey)
    {
    }

    
    public static function create(UuidInterface $aaguid, string $credentialId, ?string $credentialPublicKey): self
    {
        return new self($aaguid, $credentialId, $credentialPublicKey);
    }

    
    public function getAaguid(): UuidInterface
    {
        return $this->aaguid;
    }

    public function setAaguid(UuidInterface $aaguid): self
    {
        $this->aaguid = $aaguid;

        return $this;
    }

    
    public function getCredentialId(): string
    {
        return $this->credentialId;
    }

    
    public function getCredentialPublicKey(): ?string
    {
        return $this->credentialPublicKey;
    }

    public static function createFromArray(array $json): self
    {
        Assertion::keyExists($json, 'aaguid', 'Invalid input. "aaguid" is missing.');
        Assertion::keyExists($json, 'credentialId', 'Invalid input. "credentialId" is missing.');
        switch (true) {
            case 36 === mb_strlen($json['aaguid'], '8bit'):
                $uuid = Uuid::fromString($json['aaguid']);
                break;
            default: // Kept for compatibility with old format
                $decoded = base64_decode($json['aaguid'], true);
                $uuid = Uuid::fromBytes($decoded);
        }
        $credentialId = base64_decode($json['credentialId'], true);

        $credentialPublicKey = null;
        if (isset($json['credentialPublicKey'])) {
            $credentialPublicKey = base64_decode($json['credentialPublicKey'], true);
        }

        return new self(
            $uuid,
            $credentialId,
            $credentialPublicKey
        );
    }

    
    #[ArrayShape(['aaguid' => 'string', 'credentialId' => 'string', 'credentialPublicKey' => 'string'])]
    public function jsonSerialize(): array
    {
        $result = [
            'aaguid' => $this->aaguid->toString(),
            'credentialId' => base64_encode($this->credentialId),
        ];
        if (null !== $this->credentialPublicKey) {
            $result['credentialPublicKey'] = base64_encode($this->credentialPublicKey);
        }

        return $result;
    }
}
