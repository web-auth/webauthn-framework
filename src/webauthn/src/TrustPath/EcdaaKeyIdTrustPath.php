<?php

declare(strict_types=1);

namespace Webauthn\TrustPath;

use Assert\Assertion;

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
        Assertion::keyExists($data, 'ecdaaKeyId', 'The trust path type is invalid');
        $ecdaaKeyId = $data['ecdaaKeyId'];
        Assertion::string($ecdaaKeyId, 'The trust path type is invalid. The parameter "ecdaaKeyId" shall be a string.');

        return new self($ecdaaKeyId);
    }
}
