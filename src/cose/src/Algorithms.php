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

namespace Cose;

use Assert\Assertion;

abstract class Algorithms
{
    public const COSE_ALGORITHM_ES256 = -7;
    public const COSE_ALGORITHM_ES384 = -35;
    public const COSE_ALGORITHM_ES512 = -36;
    public const COSE_ALGORITHM_RS256 = -257;
    public const COSE_ALGORITHM_RS384 = -258;
    public const COSE_ALGORITHM_RS512 = -259;
    public const COSE_ALGORITHM_RS1 = -65535;

    public const COSE_ALGORITHM_MAP = [
        self::COSE_ALGORITHM_ES256 => OPENSSL_ALGO_SHA256,
        self::COSE_ALGORITHM_ES384 => OPENSSL_ALGO_SHA384,
        self::COSE_ALGORITHM_ES512 => OPENSSL_ALGO_SHA512,
        self::COSE_ALGORITHM_RS256 => OPENSSL_ALGO_SHA256,
        self::COSE_ALGORITHM_RS384 => OPENSSL_ALGO_SHA384,
        self::COSE_ALGORITHM_RS512 => OPENSSL_ALGO_SHA512,
        self::COSE_ALGORITHM_RS1 => OPENSSL_ALGO_SHA1,
    ];

    public const COSE_HASH_MAP = [
        self::COSE_ALGORITHM_ES256 => 'sha256',
        self::COSE_ALGORITHM_ES384 => 'sha384',
        self::COSE_ALGORITHM_ES512 => 'sha512',
        self::COSE_ALGORITHM_RS256 => 'sha256',
        self::COSE_ALGORITHM_RS384 => 'sha384',
        self::COSE_ALGORITHM_RS512 => 'sha512',
        self::COSE_ALGORITHM_RS1 => 'sha1',
    ];

    public static function getOpensslAlgorithmFor(int $algorithmIdentifier): int
    {
        Assertion::keyExists(self::COSE_ALGORITHM_MAP, $algorithmIdentifier, 'The specified algorithm identifier is not supported');

        return self::COSE_ALGORITHM_MAP[$algorithmIdentifier];
    }

    public static function getHashAlgorithmFor(int $algorithmIdentifier): string
    {
        Assertion::keyExists(self::COSE_HASH_MAP, $algorithmIdentifier, 'The specified algorithm identifier is not supported');

        return self::COSE_HASH_MAP[$algorithmIdentifier];
    }
}
