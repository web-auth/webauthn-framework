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

use Assert\Assertion;

class PublicKeyCredentialParameters implements \JsonSerializable
{
    public const ALGORITHM_ES256 = -7;
    public const ALGORITHM_RS256 = -257;

    /**
     * @var string
     */
    private $type;

    /**
     * @var int
     */
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

    public static function createFromJson(array $json): self
    {
        Assertion::keyExists($json, 'type', 'Invalid input.');
        Assertion::string($json['type'], 'Invalid input.');
        Assertion::keyExists($json, 'alg', 'Invalid input.');
        Assertion::integer($json['alg'], 'Invalid input.');

        return new self(
            $json['type'],
            $json['alg']
        );
    }

    public function jsonSerialize(): array
    {
        return [
            'type' => $this->type,
            'alg' => $this->alg,
        ];
    }
}
