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

abstract class AbstractTrustPath implements TrustPath, \JsonSerializable
{
    /**
     * @deprecated will be removed in v2.0. Use "createFromArray" instead
     */
    public static function createFromJson(array $json): self
    {
        return self::createFromArray($json);
    }

    public static function createFromArray(array $data): self
    {
        Assertion::keyExists($data, 'type', 'The trust path type is missing');
        switch ($data['type']) {
            case 'empty':
                return new EmptyTrustPath();
            case 'ecdaa_key_id':
                Assertion::keyExists($data, 'ecdaaKeyId', 'The trust path type is invalid');

                return new EcdaaKeyIdTrustPath($data['ecdaaKeyId']);
            case 'x5c':
                Assertion::keyExists($data, 'x5c', 'The trust path type is invalid');

                return new CertificateTrustPath($data['x5c']);
            default:
                throw new \InvalidArgumentException('The trust path type is invalid');
        }
    }
}
