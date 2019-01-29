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

namespace Cose\Key;

use Assert\Assertion;
use Cose\Utils\Asn1;

class RsaKey extends Key
{
    private const DATA_N = -1;
    private const DATA_E = -2;
    private const DATA_D = -3;
    private const DATA_P = -4;
    private const DATA_Q = -5;
    private const DATA_DP = -6;
    private const DATA_DQ = -7;
    private const DATA_QI = -8;
    private const DATA_OTHER = -9;
    private const DATA_RI = -10;
    private const DATA_DI = -11;
    private const DATA_TI = -12;

    public function __construct(array $data)
    {
        parent::__construct($data);
        Assertion::eq($data[self::TYPE], 3, 'Invalid RSA key. The key type does not correspond to a RSA key');
        Assertion::keyExists($data, self::DATA_N, 'Invalid RSA key. The modulus is missing');
        Assertion::keyExists($data, self::DATA_E, 'Invalid RSA key. The exponent is missing');
    }

    public function n(): string
    {
        return $this->get(self::DATA_N);
    }

    public function e(): string
    {
        return $this->get(self::DATA_E);
    }

    public function d(): string
    {
        Assertion::true($this->isPrivate(), 'The key is not private.');

        return $this->get(self::DATA_D);
    }

    public function p(): string
    {
        Assertion::true($this->isPrivate(), 'The key is not private.');

        return $this->get(self::DATA_P);
    }

    public function q(): string
    {
        Assertion::true($this->isPrivate(), 'The key is not private.');

        return $this->get(self::DATA_Q);
    }

    public function dP(): string
    {
        Assertion::true($this->isPrivate(), 'The key is not private.');

        return $this->get(self::DATA_DP);
    }

    public function dQ(): string
    {
        Assertion::true($this->isPrivate(), 'The key is not private.');

        return $this->get(self::DATA_DQ);
    }

    public function QInv(): string
    {
        Assertion::true($this->isPrivate(), 'The key is not private.');

        return $this->get(self::DATA_QI);
    }

    public function other(): array
    {
        Assertion::true($this->isPrivate(), 'The key is not private.');

        return $this->get(self::DATA_OTHER);
    }

    public function rI(): string
    {
        Assertion::true($this->isPrivate(), 'The key is not private.');

        return $this->get(self::DATA_RI);
    }

    public function dI(): string
    {
        Assertion::true($this->isPrivate(), 'The key is not private.');

        return $this->get(self::DATA_DI);
    }

    public function tI(): string
    {
        Assertion::true($this->isPrivate(), 'The key is not private.');

        return $this->get(self::DATA_TI);
    }

    public function isPrivate(): bool
    {
        return array_key_exists(self::DATA_D, $this->getData());
    }

    public function asPem(): string
    {
        Assertion::false($this->isPrivate(), 'Unsupported for private keys.');
        $der =
            Asn1::sequence(
                Asn1::sequence(
                    Asn1::oid("\x2A\x86\x48\x86\xF7\x0D\x01\x01\x01"). // OID 1.2.840.113549.1.1.1 rsaEncryption
                    Asn1::nullValue()
                ).
                Asn1::bitString(
                    Asn1::sequence(
                        Asn1::unsignedInteger($this->n()).
                        Asn1::unsignedInteger($this->e())
                    )
                )
            );

        return Asn1::pem('PUBLIC KEY', $der);
    }
}
