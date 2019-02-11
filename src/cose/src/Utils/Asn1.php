<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Cose\Utils;

class Asn1
{
    private static function length(int $len): string
    {
        if ($len < 128) {
            return \chr($len);
        }

        $lenBytes = '';
        while ($len > 0) {
            $lenBytes = \chr($len % 256).$lenBytes;
            $len = \intdiv($len, 256);
        }

        return \chr(0x80 | \mb_strlen($lenBytes, '8bit')).$lenBytes;
    }

    public static function sequence(string $contents): string
    {
        return "\x30".self::length(\mb_strlen($contents, '8bit')).$contents;
    }

    public static function oid(string $encoded): string
    {
        return "\x06".self::length(\mb_strlen($encoded, '8bit')).$encoded;
    }

    public static function unsignedInteger(string $bytes): string
    {
        $len = \mb_strlen($bytes, '8bit');

        // Remove leading zero bytes
        $i = 0;
        while ($i < ($len - 1)) {
            if (0 !== \ord($bytes[$i])) {
                break;
            }
            ++$i;
        }
        if (0 !== $i) {
            $bytes = \mb_substr($bytes, $i);
        }

        // If most significant bit is set, prefix with another zero to prevent it being seen as negative number
        if (0 !== (\ord($bytes[0]) & 0x80)) {
            $bytes = "\x00".$bytes;
        }

        return "\x02".self::length(\mb_strlen($bytes, '8bit')).$bytes;
    }

    public static function bitString(string $bytes): string
    {
        $len = \mb_strlen($bytes, '8bit') + 1;

        return "\x03".self::length($len)."\x00".$bytes;
    }

    public static function nullValue(): string
    {
        return "\x05\x00";
    }

    public static function pem(string $type, string $der): string
    {
        return \Safe\sprintf("-----BEGIN %s-----\n", mb_strtoupper($type)).
            chunk_split(base64_encode($der), 64, "\n").
            \Safe\sprintf("-----END %s-----\n", mb_strtoupper($type));
    }
}
