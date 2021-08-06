<?php

declare(strict_types=1);

namespace Webauthn\TrustPath;

use JetBrains\PhpStorm\ArrayShape;
use JetBrains\PhpStorm\Pure;

final class EmptyTrustPath implements TrustPath
{
    #[Pure]
    public static function create(): self
    {
        return new self();
    }

    /**
     * @return string[]
     */
    #[Pure]
    #[ArrayShape(['type' => 'string'])]
    public function jsonSerialize(): array
    {
        return [
            'type' => self::class,
        ];
    }

    /**
     * {@inheritdoc}
     */
    #[Pure]
    public static function createFromArray(array $data): TrustPath
    {
        return self::create();
    }
}
