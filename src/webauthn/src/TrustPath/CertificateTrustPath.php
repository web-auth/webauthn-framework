<?php

declare(strict_types=1);

namespace Webauthn\TrustPath;

use Assert\Assertion;
use JetBrains\PhpStorm\ArrayShape;

final class CertificateTrustPath implements TrustPath
{

    public function __construct(private array $certificates)
    {
    }


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
    public static function createFromArray(array $data): TrustPath
    {
        Assertion::keyExists($data, 'x5c', 'The trust path type is invalid');

        return CertificateTrustPath::create($data['x5c']);
    }


    #[ArrayShape(['type' => 'string', 'x5c' => 'array'])]
    public function jsonSerialize(): array
    {
        return [
            'type' => self::class,
            'x5c' => $this->certificates,
        ];
    }
}
