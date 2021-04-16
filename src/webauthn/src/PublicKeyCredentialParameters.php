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

namespace Webauthn;

use Assert\Assertion;
use JetBrains\PhpStorm\ArrayShape;
use JetBrains\PhpStorm\Pure;
use JsonSerializable;
use function Safe\json_decode;

class PublicKeyCredentialParameters implements JsonSerializable
{
    #[Pure]
    public function __construct(private string $type, private int $alg)
    {
    }

    #[Pure]
    public function getType(): string
    {
        return $this->type;
    }

    #[Pure]
    public function getAlg(): int
    {
        return $this->alg;
    }

    public static function createFromString(string $data): self
    {
        $data = json_decode($data, true);
        Assertion::isArray($data, 'Invalid data');

        return self::createFromArray($data);
    }

    /**
     * @param mixed[] $json
     */
    public static function createFromArray(array $json): self
    {
        Assertion::keyExists($json, 'type', 'Invalid input. "type" is missing.');
        Assertion::string($json['type'], 'Invalid input. "type" is not a string.');
        Assertion::keyExists($json, 'alg', 'Invalid input. "alg" is missing.');
        Assertion::integer($json['alg'], 'Invalid input. "alg" is not an integer.');

        return new self(
            $json['type'],
            $json['alg']
        );
    }

    #[Pure]
    #[ArrayShape(['type' => 'string', 'alg' => 'int'])]
    public function jsonSerialize(): array
    {
        return [
            'type' => $this->type,
            'alg' => $this->alg,
        ];
    }
}
