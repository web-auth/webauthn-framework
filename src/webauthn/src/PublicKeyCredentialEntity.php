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

use JetBrains\PhpStorm\ArrayShape;
use JetBrains\PhpStorm\Pure;
use JsonSerializable;

abstract class PublicKeyCredentialEntity implements JsonSerializable
{
    public function __construct(protected string $name, protected ?string $icon)
    {
    }

    public function getName(): string
    {
        return $this->name;
    }

    public function getIcon(): ?string
    {
        return $this->icon;
    }

    #[ArrayShape(['name' => 'string', 'icon' => 'null|string'])]
    #[Pure]
    public function jsonSerialize(): array
    {
        $json = [
            'name' => $this->name,
        ];
        if (null !== $this->icon) {
            $json['icon'] = $this->icon;
        }

        return $json;
    }
}
