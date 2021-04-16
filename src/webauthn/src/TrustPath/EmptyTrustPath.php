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

use JetBrains\PhpStorm\ArrayShape;
use JetBrains\PhpStorm\Pure;

final class EmptyTrustPath implements TrustPath
{
    #[Pure]
    public static function create(): self
    {
        return new self();
    }

    /**
     * @return string[]
     */
    #[Pure]
    #[ArrayShape(['type' => 'string'])]
    public function jsonSerialize(): array
    {
        return [
            'type' => self::class,
        ];
    }

    /**
     * {@inheritdoc}
     */
    #[Pure]
    public static function createFromArray(array $data): TrustPath
    {
        return self::create();
    }
}
