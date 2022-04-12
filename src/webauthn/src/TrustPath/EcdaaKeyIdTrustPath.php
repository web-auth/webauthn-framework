<?php

declare(strict_types=1);

namespace Webauthn\TrustPath;

use Assert\Assertion;

final class EcdaaKeyIdTrustPath implements TrustPath
{
    public function __construct(
        private readonly string $ecdaaKeyId
    ) {
    }

    public function getEcdaaKeyId(): string
    {
        return $this->ecdaaKeyId;
    }

    /**
     * @return string[]
     */
    public function jsonSerialize(): array
    {
        return [
            'type' => self::class,
            'ecdaaKeyId' => $this->ecdaaKeyId,
        ];
    }

    /**
     * {@inheritdoc}
     */
    public static function createFromArray(array $data): static
    {
        Assertion::keyExists($data, 'ecdaaKeyId', 'The trust path type is invalid');

        return new self($data['ecdaaKeyId']);
    }
}
