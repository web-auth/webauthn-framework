<?php

declare(strict_types=1);

namespace Webauthn\MetadataService;

/**
 * @internal
 */
abstract class Utils
{
    public static function filterNullValues(array $data): array
    {
        return array_filter($data, static function ($var): bool {return $var !== null; });
    }
}
