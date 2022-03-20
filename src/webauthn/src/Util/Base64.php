<?php

declare(strict_types=1);

namespace Webauthn\Util;

use Assert\Assertion;
use InvalidArgumentException;
use ParagonIE\ConstantTime\Base64UrlSafe;
use Throwable;

abstract class Base64
{
    public static function decodeUrlSafe(string $data): string
    {
        Assertion::regex($data, '/([A-Z][a-z][0-9]\-_)*/', 'Invalid Base 64 Url Safe character');

        return Base64UrlSafe::decode($data);
    }

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
