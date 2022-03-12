<?php

declare(strict_types=1);

namespace Webauthn;

use Assert\Assertion;
use Base64Url\Base64Url;
use InvalidArgumentException;
use JetBrains\PhpStorm\ArrayShape;
use JsonSerializable;
use Ramsey\Uuid\Uuid;
use Ramsey\Uuid\UuidInterface;
use function Safe\base64_decode;
use function Safe\sprintf;
use Throwable;
use Webauthn\TrustPath\TrustPath;
use Webauthn\TrustPath\TrustPathLoader;

/**
 * @see https://www.w3.org/TR/webauthn/#iface-pkcredential
 */
class PublicKeyCredentialSource implements JsonSerializable
{
    
    public function __construct(
        protected string $publicKeyCredentialId,
        protected string $type,
        protected array $transports,
        protected string $attestationType,
        protected TrustPath $trustPath,
        protected UuidInterface $aaguid,
        protected string $credentialPublicKey,
        protected string $userHandle,
        protected int $counter,
        protected ?array $otherUI = null
    ) {
    }

    
    public static function create(string $publicKeyCredentialId, string $type, array $transports, string $attestationType, TrustPath $trustPath, UuidInterface $aaguid, string $credentialPublicKey, string $userHandle, int $counter, ?array $otherUI = null): self
    {
        return new self($publicKeyCredentialId, $type, $transports, $attestationType, $trustPath, $aaguid, $credentialPublicKey, $userHandle, $counter, $otherUI);
    }

    
    public function getPublicKeyCredentialId(): string
    {
        return $this->publicKeyCredentialId;
    }

    
    public function getPublicKeyCredentialDescriptor(): PublicKeyCredentialDescriptor
    {
        return PublicKeyCredentialDescriptor::create(
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
        return AttestedCredentialData::create(
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

    
    public function getAaguid(): UuidInterface
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

    public function setCounter(int $counter): self
    {
        $this->counter = $counter;

        return $this;
    }

    
    public function getOtherUI(): ?array
    {
        return $this->otherUI;
    }

    public function setOtherUI(?array $otherUI): self
    {
        $this->otherUI = $otherUI;

        return $this;
    }

    public static function createFromArray(array $data): self
    {
        $keys = array_keys(get_class_vars(self::class));
        $otherUIKey = array_search('otherUI', $keys, true);
        if (false !== $otherUIKey) {
            unset($keys[$otherUIKey]);
        }
        foreach ($keys as $key) {
            Assertion::keyExists($data, $key, sprintf('The parameter "%s" is missing', $key));
        }
        switch (true) {
            case 36 === mb_strlen($data['aaguid'], '8bit'):
                $uuid = Uuid::fromString($data['aaguid']);
                break;
            default: // Kept for compatibility with old format
                $decoded = base64_decode($data['aaguid'], true);
                $uuid = Uuid::fromBytes($decoded);
        }

        try {
            return new self(
                Base64Url::decode($data['publicKeyCredentialId']),
                $data['type'],
                $data['transports'],
                $data['attestationType'],
                TrustPathLoader::loadTrustPath($data['trustPath']),
                $uuid,
                Base64Url::decode($data['credentialPublicKey']),
                Base64Url::decode($data['userHandle']),
                $data['counter'],
                $data['otherUI'] ?? null
            );
        } catch (Throwable $throwable) {
            throw new InvalidArgumentException('Unable to load the data', $throwable->getCode(), $throwable);
        }
    }

    #[ArrayShape(['publicKeyCredentialId' => 'string', 'type' => 'string', 'transports' => 'array', 'attestationType' => 'string', 'trustPath' => 'mixed', 'aaguid' => 'string', 'credentialPublicKey' => 'string', 'userHandle' => 'string', 'counter' => 'int', 'otherUI' => 'null|array'])]
    public function jsonSerialize(): array
    {
        return [
            'publicKeyCredentialId' => Base64Url::encode($this->publicKeyCredentialId),
            'type' => $this->type,
            'transports' => $this->transports,
            'attestationType' => $this->attestationType,
            'trustPath' => $this->trustPath->jsonSerialize(),
            'aaguid' => $this->aaguid->toString(),
            'credentialPublicKey' => Base64Url::encode($this->credentialPublicKey),
            'userHandle' => Base64Url::encode($this->userHandle),
            'counter' => $this->counter,
            'otherUI' => $this->otherUI,
        ];
    }
}
