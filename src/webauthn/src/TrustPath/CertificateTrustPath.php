<?php

declare(strict_types=1);

namespace Webauthn\TrustPath;

use function array_key_exists;
use function is_array;
use Webauthn\Exception\InvalidTrustPathException;

final class CertificateTrustPath implements TrustPath
{
    /**
     * @param string[] $certificates
     */
    public function __construct(
        public readonly array $certificates
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
     * @deprecated since 4.7.0. Please use the property directly.
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
        array_key_exists('x5c', $data) || throw InvalidTrustPathException::create('The trust path type is invalid');
        $x5c = $data['x5c'];
        is_array($x5c) || throw InvalidTrustPathException::create(
            'The trust path type is invalid. The parameter "x5c" shall contain strings.'
        );

        return self::create($x5c);
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
