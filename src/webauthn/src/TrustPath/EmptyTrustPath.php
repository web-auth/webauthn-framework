<?php

declare(strict_types=1);

namespace Webauthn\TrustPath;

final class EmptyTrustPath implements TrustPath
{
    /**
     * @return string[]
     */
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
        return new self();
    }
}
