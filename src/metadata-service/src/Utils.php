<?php

declare(strict_types=1);

namespace Webauthn\MetadataService;

/**
 * @internal
 */
abstract class Utils
{
    /**
     * @param array<mixed> $data
     *
     * @return array<mixed>
     */
    public static function filterNullValues(array $data): array
    {
        return array_filter($data, static fn ($var): bool => $var !== null);
    }
}
