<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2019 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Webauthn\TrustPath;

use Assert\Assertion;
use InvalidArgumentException;
use function Safe\class_implements;
use function Safe\sprintf;

abstract class TrustPathLoader
{
    public static function loadTrustPath(array $data): TrustPath
    {
        Assertion::keyExists($data, 'type', 'The trust path type is missing');
        $type = $data['type'];
        $oldTypes = self::oldTrustPathTypes();
        switch (true) {
            case class_exists($type) && \in_array(TrustPath::class, class_implements($type), true):
                return $type::createFromArray($data);
            case \array_key_exists($type, $oldTypes):
                return ($oldTypes[$type])::createFromArray($data);
            default:
                throw new InvalidArgumentException(sprintf('The trust path type "%s" is not supported', $data['type']));
        }
    }

    private static function oldTrustPathTypes(): array
    {
        return [
            'empty' => EmptyTrustPath::class,
            'ecdaa_key_id' => EcdaaKeyIdTrustPath::class,
            'x5c' => CertificateTrustPath::class,
        ];
    }
}
