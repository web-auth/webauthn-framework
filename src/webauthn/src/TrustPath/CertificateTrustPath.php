<?php

declare(strict_types=1);

namespace Webauthn\TrustPath;

use Assert\Assertion;

final class CertificateTrustPath implements TrustPath
{
    /**
     * @param string[] $certificates
     */
    public function __construct(
        private readonly array $certificates
    ) {
    }

    /**
     * @param string[] $certificates
     */
    public static function create(array $certificates): self
    {
        return new self($certificates);
    }

    /**
     * @return string[]
     */
    public function getCertificates(): array
    {
        return $this->certificates;
    }

    /**
     * {@inheritdoc}
     */
    public static function createFromArray(array $data): static
    {
        Assertion::keyExists($data, 'x5c', 'The trust path type is invalid');

        return new self($data['x5c']);
    }

    /**
     * @return mixed[]
     */
    public function jsonSerialize(): array
    {
        return [
            'type' => self::class,
            'x5c' => $this->certificates,
        ];
    }
}
