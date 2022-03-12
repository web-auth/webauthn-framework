<?php

declare(strict_types=1);

namespace Webauthn\TrustPath;

use Assert\Assertion;
use JetBrains\PhpStorm\ArrayShape;

final class EcdaaKeyIdTrustPath implements TrustPath
{

    public function __construct(private string $ecdaaKeyId)
    {
    }


    public static function create(string $ecdaaKeyId): self
    {
        return new self($ecdaaKeyId);
    }


    public function getEcdaaKeyId(): string
    {
        return $this->ecdaaKeyId;
    }

    /**
     * @return string[]
     */

    #[ArrayShape(['type' => 'string', 'ecdaaKeyId' => 'string'])]
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
    public static function createFromArray(array $data): TrustPath
    {
        Assertion::keyExists($data, 'ecdaaKeyId', 'The trust path type is invalid');

        return EcdaaKeyIdTrustPath::create($data['ecdaaKeyId']);
    }
}
