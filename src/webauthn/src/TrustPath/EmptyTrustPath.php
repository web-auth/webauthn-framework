<?php

declare(strict_types=1);

namespace Webauthn\TrustPath;

use JetBrains\PhpStorm\ArrayShape;

final class EmptyTrustPath implements TrustPath
{
    
    public static function create(): self
    {
        return new self();
    }

    /**
     * @return string[]
     */
    
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
    
    public static function createFromArray(array $data): TrustPath
    {
        return self::create();
    }
}
