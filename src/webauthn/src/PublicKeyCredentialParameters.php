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

namespace Webauthn;

use Assert\Assertion;

class PublicKeyCredentialParameters implements \JsonSerializable
{
    /**
     * @deprecated Will be removed in v2.0. Use \Cose\Algorithms::COSE_ALGORITHM_ES256 instead
     */
    public const ALGORITHM_ES256 = -7;

    /**
     * @deprecated Will be removed in v2.0. Use \Cose\Algorithms::COSE_ALGORITHM_RS256 instead
     */
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

    /**
     * @deprecated will be removed in v2.0. Use "createFromArray" instead
     */
    public static function createFromJson(array $json): self
    {
        return self::createFromArray($json);
    }

    public static function createFromString(string $data): self
    {
        $data = \Safe\json_decode($data, true);
        Assertion::isArray($data, 'Invalid data');

        return self::createFromArray($data);
    }

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

    public function jsonSerialize(): array
    {
        return [
            'type' => $this->type,
            'alg' => $this->alg,
        ];
    }
}
