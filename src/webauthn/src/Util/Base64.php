<?php

declare(strict_types=1);

namespace Webauthn\Util;

use InvalidArgumentException;
use ParagonIE\ConstantTime\Base64UrlSafe;
use Throwable;

abstract class Base64
{
    public static function decode(string $data): string
    {
        try {
            return Base64UrlSafe::decode($data);
        } catch (Throwable) {
        }

        try {
            return \ParagonIE\ConstantTime\Base64::decode($data, true);
        } catch (Throwable $e) {
            throw new InvalidArgumentException('Invalid data submitted', 0, $e);
        }
    }
}
