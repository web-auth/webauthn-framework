<?php

declare(strict_types=1);

namespace Webauthn\Tests\Unit\TrustPath;

use Webauthn\TrustPath\TrustPath;

final class FooTrustPath implements TrustPath
{
    /**
     * {@inheritdoc}
     */
    public static function createFromArray(array $data): TrustPath
    {
        return new self();
    }

    public function jsonSerialize()
    {
        return [
            'type' => self::class,
        ];
    }
}
