<?php

declare(strict_types=1);

namespace Webauthn\MetadataService;

use JetBrains\PhpStorm\Pure;
use LogicException;
use Throwable;

/**
 * @internal
 */
abstract class Utils
{
    public static function logicException(string $message, ?Throwable $previousException = null): callable
    {
        return static function () use ($message, $previousException): LogicException {
            return new LogicException($message, 0, $previousException);
        };
    }

    #[Pure]
    public static function filterNullValues(array $data): array
    {
        return array_filter($data, static function ($var): bool {return null !== $var; });
    }
}
