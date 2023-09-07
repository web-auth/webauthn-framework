<?php

declare(strict_types=1);

namespace Webauthn\Tests\Unit\TrustPath;

use Webauthn\TrustPath\TrustPath;

final class FooTrustPath implements TrustPath
{
    public static function createFromArray(array $data): static
    {
        return new self();
    }

    /**
     * @return array<string, string>
     */
    public function jsonSerialize(): array
    {
        return [
            'type' => self::class,
        ];
    }
}
