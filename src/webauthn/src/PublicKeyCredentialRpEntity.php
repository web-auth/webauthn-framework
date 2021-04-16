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

class PublicKeyCredentialRpEntity extends PublicKeyCredentialEntity
{
    #[Pure]
    public function __construct(string $name, protected ?string $id = null, ?string $icon = null)
    {
        parent::__construct($name, $icon);
    }

    #[Pure]
    public function getId(): ?string
    {
        return $this->id;
    }

    public static function createFromArray(array $json): self
    {
        Assertion::keyExists($json, 'name', 'Invalid input. "name" is missing.');

        return new self(
            $json['name'],
            $json['id'] ?? null,
            $json['icon'] ?? null
        );
    }

    #[Pure]
    #[ArrayShape(['name' => 'string', 'icon' => "\null|string", 'id' => 'null|string'])]
    public function jsonSerialize(): array
    {
        $json = parent::jsonSerialize();
        if (null !== $this->id) {
            $json['id'] = $this->id;
        }

        return $json;
    }
}
