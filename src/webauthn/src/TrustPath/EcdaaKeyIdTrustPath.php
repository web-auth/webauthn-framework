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

namespace Webauthn\TrustPath;

use Assert\Assertion;
use JetBrains\PhpStorm\ArrayShape;
use JetBrains\PhpStorm\Pure;

final class EcdaaKeyIdTrustPath implements TrustPath
{
    #[Pure]
    public function __construct(private string $ecdaaKeyId)
    {
    }

    #[Pure]
    public static function create(string $ecdaaKeyId): self
    {
        return new self($ecdaaKeyId);
    }

    #[Pure]
    public function getEcdaaKeyId(): string
    {
        return $this->ecdaaKeyId;
    }

    /**
     * @return string[]
     */
    #[Pure]
    #[ArrayShape(['type' => 'string', 'ecdaaKeyId' => 'string'])]
    public function jsonSerialize(): array
    {
        return [
            'type' => self::class,
            'ecdaaKeyId' => $this->ecdaaKeyId,
        ];
    }

    /**
     * {@inheritdoc}
     */
    public static function createFromArray(array $data): TrustPath
    {
        Assertion::keyExists($data, 'ecdaaKeyId', 'The trust path type is invalid');

        return EcdaaKeyIdTrustPath::create($data['ecdaaKeyId']);
    }
}
