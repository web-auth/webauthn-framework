<?php

declare(strict_types=1);

namespace Webauthn\TrustPath;

use function array_key_exists;
use Assert\Assertion;
use InvalidArgumentException;

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
        array_key_exists('x5c', $data) || throw new InvalidArgumentException('The trust path type is invalid');
        $x5c = $data['x5c'];
        Assertion::isArray($x5c, 'The trust path type is invalid. The parameter "x5c" shall contain strings.');
        Assertion::allString($x5c, 'The trust path type is invalid. The parameter "x5c" shall contain strings.');

        return new self($x5c);
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
