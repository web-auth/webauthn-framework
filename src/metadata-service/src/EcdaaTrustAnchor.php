<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2020 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Webauthn\MetadataService;

use Assert\Assertion;
use JsonSerializable;
use ParagonIE\ConstantTime\Base64UrlSafe;
use function Safe\sprintf;

class EcdaaTrustAnchor implements JsonSerializable
{
    /**
     * @var string
     */
    private $X;

    /**
     * @var string
     */
    private $Y;

    /**
     * @var string
     */
    private $c;

    /**
     * @var string
     */
    private $sx;

    /**
     * @var string
     */
    private $sy;

    /**
     * @var string
     */
    private $G1Curve;

    public function __construct(string $X, string $Y, string $c, string $sx, string $sy, string $G1Curve)
    {
        $this->X = $X;
        $this->Y = $Y;
        $this->c = $c;
        $this->sx = $sx;
        $this->sy = $sy;
        $this->G1Curve = $G1Curve;
    }

    public function getX(): string
    {
        return $this->X;
    }

    public function getY(): string
    {
        return $this->Y;
    }

    public function getC(): string
    {
        return $this->c;
    }

    public function getSx(): string
    {
        return $this->sx;
    }

    public function getSy(): string
    {
        return $this->sy;
    }

    public function getG1Curve(): string
    {
        return $this->G1Curve;
    }

    public static function createFromArray(array $data): self
    {
        $data = Utils::filterNullValues($data);
        foreach (['X', 'Y', 'c', 'sx', 'sy', 'G1Curve'] as $key) {
            Assertion::keyExists($data, $key, sprintf('Invalid data. The key "%s" is missing', $key));
        }

        return new self(
            Base64UrlSafe::decode($data['X']),
            Base64UrlSafe::decode($data['Y']),
            Base64UrlSafe::decode($data['c']),
            Base64UrlSafe::decode($data['sx']),
            Base64UrlSafe::decode($data['sy']),
            $data['G1Curve']
        );
    }

    public function jsonSerialize(): array
    {
        $data = [
            'X' => Base64UrlSafe::encodeUnpadded($this->X),
            'Y' => Base64UrlSafe::encodeUnpadded($this->Y),
            'c' => Base64UrlSafe::encodeUnpadded($this->c),
            'sx' => Base64UrlSafe::encodeUnpadded($this->sx),
            'sy' => Base64UrlSafe::encodeUnpadded($this->sy),
            'G1Curve' => $this->G1Curve,
        ];

        return Utils::filterNullValues($data);
    }
}
