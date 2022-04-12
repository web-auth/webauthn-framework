<?php

declare(strict_types=1);

namespace Webauthn\MetadataService\Statement;

use Assert\Assertion;
use JsonSerializable;

class RgbPaletteEntry implements JsonSerializable
{
    private readonly int $r;

    private readonly int $g;

    private readonly int $b;

    public function __construct(int $r, int $g, int $b)
    {
        Assertion::range($r, 0, 255, 'The key "r" is invalid');
        Assertion::range($g, 0, 255, 'The key "g" is invalid');
        Assertion::range($b, 0, 255, 'The key "b" is invalid');
        $this->r = $r;
        $this->g = $g;
        $this->b = $b;
    }

    public function getR(): int
    {
        return $this->r;
    }

    public function getG(): int
    {
        return $this->g;
    }

    public function getB(): int
    {
        return $this->b;
    }

    /**
     * @param array<string, mixed> $data
     */
    public static function createFromArray(array $data): self
    {
        foreach (['r', 'g', 'b'] as $key) {
            Assertion::keyExists($data, $key, sprintf('The key "%s" is missing', $key));
            Assertion::integer($data[$key], sprintf('The key "%s" is invalid', $key));
        }

        return new self($data['r'], $data['g'], $data['b']);
    }

    /**
     * @return array<string, int>
     */
    public function jsonSerialize(): array
    {
        return [
            'r' => $this->r,
            'g' => $this->g,
            'b' => $this->b,
        ];
    }
}
