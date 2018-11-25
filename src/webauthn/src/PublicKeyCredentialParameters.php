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

namespace Webauthn;

class PublicKeyCredentialParameters implements \JsonSerializable
{
    public const ALGORITHM_ES256 = -7;
    public const ALGORITHM_RS256 = -257;

    private $type;

    private $alg;

    public function __construct(string $type, int $alg)
    {
        $this->type = $type;
        $this->alg = $alg;
    }

    public function getType(): string
    {
        return $this->type;
    }

    public function getAlg(): int
    {
        return $this->alg;
    }

    public function jsonSerialize(): array
    {
        return [
            'type' => $this->type,
            'alg' => $this->alg,
        ];
    }
}
