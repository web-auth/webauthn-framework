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

class PublicKeyCredentialRpEntity extends PublicKeyCredentialEntity
{
    private $id;

    public function __construct(string $name, ?string $id = null, ?string $icon = null)
    {
        parent::__construct($name, $icon);
        $this->id = $id;
    }

    public function getId(): ?string
    {
        return $this->id;
    }

    public function jsonSerialize(): array
    {
        $json = parent::jsonSerialize();
        if ($this->id) {
            $json['id'] = $this->id;
        }

        return $json;
    }
}
