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

    /**
     * @deprecated since 4.8.0. Please use {Webauthn\Denormalizer\WebauthnSerializerFactory} for converting the object.
     * @infection-ignore-all
     */
    public static function createFromArray(array $data): static
    {
        return self::create();
    }
}
