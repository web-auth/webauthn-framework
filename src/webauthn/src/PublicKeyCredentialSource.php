<?php

declare(strict_types=1);

namespace Webauthn;

use Assert\Assertion;
use InvalidArgumentException;
use JsonSerializable;
use ParagonIE\ConstantTime\Base64UrlSafe;
use Symfony\Component\Uid\AbstractUid;
use Symfony\Component\Uid\Uuid;
use Throwable;
use Webauthn\TrustPath\TrustPath;
use Webauthn\TrustPath\TrustPathLoader;

/**
 * @see https://www.w3.org/TR/webauthn/#iface-pkcredential
 */
class PublicKeyCredentialSource implements JsonSerializable
{
    /**
     * @var string[]
     */
    protected array $transports;

    /**
     * @param string[] $transports
     */
    public function __construct(
        protected string $publicKeyCredentialId,
        protected string $type,
        array $transports,
        protected string $attestationType,
        protected TrustPath $trustPath,
        protected AbstractUid $aaguid,
        protected string $credentialPublicKey,
        protected string $userHandle,
        protected int $counter,
        protected ?array $otherUI = null
    ) {
        $this->transports = $transports;
    }

    public function getPublicKeyCredentialId(): string
    {
        return $this->publicKeyCredentialId;
    }

    public function getPublicKeyCredentialDescriptor(): PublicKeyCredentialDescriptor
    {
        return new PublicKeyCredentialDescriptor($this->type, $this->publicKeyCredentialId, $this->transports);
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
        return new AttestedCredentialData($this->aaguid, $this->publicKeyCredentialId, $this->credentialPublicKey);
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

    public function getAaguid(): AbstractUid
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

    public function getOtherUI(): ?array
    {
        return $this->otherUI;
    }

    public function setOtherUI(?array $otherUI): self
    {
        $this->otherUI = $otherUI;

        return $this;
    }

    /**
     * @param mixed[] $data
     */
    public static function createFromArray(array $data): self
    {
        $keys = array_keys(get_class_vars(self::class));
        foreach ($keys as $key) {
            if ($key === 'otherUI') {
                continue;
            }
            Assertion::keyExists($data, $key, sprintf('The parameter "%s" is missing', $key));
        }
        Assertion::length($data['aaguid'], 36, 'Invalid AAGUID', null, '8bit');
        $uuid = Uuid::fromString($data['aaguid']);

        try {
            return new self(
                Base64UrlSafe::decode($data['publicKeyCredentialId']),
                $data['type'],
                $data['transports'],
                $data['attestationType'],
                TrustPathLoader::loadTrustPath($data['trustPath']),
                $uuid,
                Base64UrlSafe::decode($data['credentialPublicKey']),
                Base64UrlSafe::decode($data['userHandle']),
                $data['counter'],
                $data['otherUI'] ?? null
            );
        } catch (Throwable $throwable) {
            throw new InvalidArgumentException('Unable to load the data', $throwable->getCode(), $throwable);
        }
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
            'trustPath' => $this->trustPath->jsonSerialize(),
            'aaguid' => $this->aaguid->__toString(),
            'credentialPublicKey' => Base64UrlSafe::encodeUnpadded($this->credentialPublicKey),
            'userHandle' => Base64UrlSafe::encodeUnpadded($this->userHandle),
            'counter' => $this->counter,
            'otherUI' => $this->otherUI,
        ];
    }
}
