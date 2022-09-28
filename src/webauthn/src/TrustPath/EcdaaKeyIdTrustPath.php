<?php

declare(strict_types=1);

namespace Webauthn\TrustPath;

use function array_key_exists;
use Webauthn\Exception\InvalidTrustPathException;

/**
 * @deprecated since 4.2.0 and will be removed in 5.0.0. The ECDAA Trust Anchor does no longer exist in Webauthn specification.
 */
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
        array_key_exists('ecdaaKeyId', $data) || throw InvalidTrustPathException::create(
            'The trust path type is invalid'
        );

        return new self($data['ecdaaKeyId']);
    }
}
