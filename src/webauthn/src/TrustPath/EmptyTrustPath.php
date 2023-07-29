<?php

declare(strict_types=1);

namespace Webauthn\TrustPath;

final class EmptyTrustPath implements TrustPath
{
    public static function create(): self
    {
        return new self();
    }

    /**
     * @return string[]
     */
    public function jsonSerialize(): array
    {
        return [
            'type' => self::class,
        ];
    }

    public static function createFromArray(array $data): static
    {
        return self::create();
    }
}
