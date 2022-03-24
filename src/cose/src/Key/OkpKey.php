<?php

declare(strict_types=1);

namespace Cose\Key;

use function array_key_exists;
use Assert\Assertion;

class OkpKey extends Key
{
    public const CURVE_X25519 = 4;

    public const CURVE_X448 = 5;

    public const CURVE_ED25519 = 6;

    public const CURVE_ED448 = 7;

    public const DATA_CURVE = -1;

    public const DATA_X = -2;

    public const DATA_D = -4;

    private const SUPPORTED_CURVES = [
        self::CURVE_X25519,
        self::CURVE_X448,
        self::CURVE_ED25519,
        self::CURVE_ED448,
    ];

    /**
     * @param array<int|string, mixed> $data
     */
    public function __construct(array $data)
    {
        parent::__construct($data);
        Assertion::eq(
            $data[self::TYPE],
            self::TYPE_OKP,
            'Invalid OKP key. The key type does not correspond to an OKP key'
        );
        Assertion::keyExists($data, self::DATA_CURVE, 'Invalid EC2 key. The curve is missing');
        Assertion::keyExists($data, self::DATA_X, 'Invalid OKP key. The x coordinate is missing');
        Assertion::inArray((int) $data[self::DATA_CURVE], self::SUPPORTED_CURVES, 'The curve is not supported');
    }

    /**
     * @param array<int|string, mixed> $data
     */
    public static function create(array $data): self
    {
        return new self($data);
    }

    public function x(): string
    {
        return $this->get(self::DATA_X);
    }

    public function isPrivate(): bool
    {
        return array_key_exists(self::DATA_D, $this->getData());
    }

    public function d(): string
    {
        Assertion::true($this->isPrivate(), 'The key is not private');

        return $this->get(self::DATA_D);
    }

    public function curve(): int
    {
        return (int) $this->get(self::DATA_CURVE);
    }
}
