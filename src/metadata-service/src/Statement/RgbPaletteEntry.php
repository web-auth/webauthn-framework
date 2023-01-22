<?php

declare(strict_types=1);

namespace Webauthn\MetadataService\Statement;

use function array_key_exists;
use function is_int;
use JsonSerializable;
use Webauthn\MetadataService\Exception\MetadataStatementLoadingException;

/**
 * @final
 */
class RgbPaletteEntry implements JsonSerializable
{
    private readonly int $r;

    private readonly int $g;

    private readonly int $b;

    public function __construct(int $r, int $g, int $b)
    {
        ($r >= 0 && $r <= 255) || throw MetadataStatementLoadingException::create('The key "r" is invalid');
        ($g >= 0 && $g <= 255) || throw MetadataStatementLoadingException::create('The key "g" is invalid');
        ($b >= 0 && $b <= 255) || throw MetadataStatementLoadingException::create('The key "b" is invalid');
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
            array_key_exists($key, $data) || throw MetadataStatementLoadingException::create(sprintf(
                'The key "%s" is missing',
                $key
            ));
            is_int($data[$key]) || throw MetadataStatementLoadingException::create(
                sprintf('The key "%s" is invalid', $key)
            );
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
