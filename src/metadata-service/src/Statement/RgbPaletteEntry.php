<?php

declare(strict_types=1);

namespace Webauthn\MetadataService\Statement;

use JsonSerializable;
use Webauthn\MetadataService\Exception\MetadataStatementLoadingException;

class RgbPaletteEntry implements JsonSerializable
{
    public function __construct(
        public readonly int $r,
        public readonly int $g,
        public readonly int $b,
    ) {
        ($r >= 0 && $r <= 255) || throw MetadataStatementLoadingException::create('The key "r" is invalid');
        ($g >= 0 && $g <= 255) || throw MetadataStatementLoadingException::create('The key "g" is invalid');
        ($b >= 0 && $b <= 255) || throw MetadataStatementLoadingException::create('The key "b" is invalid');
    }

    public static function create(int $r, int $g, int $b): self
    {
        return new self($r, $g, $b);
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
