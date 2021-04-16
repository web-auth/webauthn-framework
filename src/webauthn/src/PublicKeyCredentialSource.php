<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2020 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Webauthn;

use Assert\Assertion;
use Base64Url\Base64Url;
use InvalidArgumentException;
use JetBrains\PhpStorm\ArrayShape;
use JetBrains\PhpStorm\Pure;
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
    /*
     * @var string[]
     */

    #[Pure]
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

    #[Pure]
    public function getPublicKeyCredentialId(): string
    {
        return $this->publicKeyCredentialId;
    }

    #[Pure]
    public function getPublicKeyCredentialDescriptor(): PublicKeyCredentialDescriptor
    {
        return new PublicKeyCredentialDescriptor(
            $this->type,
            $this->publicKeyCredentialId,
            $this->transports
        );
    }

    #[Pure]
    public function getAttestationType(): string
    {
        return $this->attestationType;
    }

    #[Pure]
    public function getTrustPath(): TrustPath
    {
        return $this->trustPath;
    }

    #[Pure]
    public function getAttestedCredentialData(): AttestedCredentialData
    {
        return new AttestedCredentialData(
            $this->aaguid,
            $this->publicKeyCredentialId,
            $this->credentialPublicKey
        );
    }

    #[Pure]
    public function getType(): string
    {
        return $this->type;
    }

    /**
     * @return string[]
     */
    #[Pure]
    public function getTransports(): array
    {
        return $this->transports;
    }

    #[Pure]
    public function getAaguid(): UuidInterface
    {
        return $this->aaguid;
    }

    #[Pure]
    public function getCredentialPublicKey(): string
    {
        return $this->credentialPublicKey;
    }

    #[Pure]
    public function getUserHandle(): string
    {
        return $this->userHandle;
    }

    #[Pure]
    public function getCounter(): int
    {
        return $this->counter;
    }

    public function setCounter(int $counter): self
    {
        $this->counter = $counter;

        return $this;
    }

    #[Pure]
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
                $data['counter']
            );
        } catch (Throwable $throwable) {
            throw new InvalidArgumentException('Unable to load the data', $throwable->getCode(), $throwable);
        }
    }

    #[ArrayShape(['publicKeyCredentialId' => 'string', 'type' => 'string', 'transports' => 'array', 'attestationType' => 'string', 'trustPath' => 'mixed', 'aaguid' => 'string', 'credentialPublicKey' => 'string', 'userHandle' => 'string', 'counter' => 'int'])]
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
        ];
    }
}
