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

class PublicKeyCredentialUserEntity extends PublicKeyCredentialEntity
{
    private $id;

    private $displayName;

    public function __construct(string $name, string $id, string $displayName, ?string $icon = null)
    {
        parent::__construct($name, $icon);
        $this->id = $id;
        $this->displayName = $displayName;
    }

    public function getId(): string
    {
        return $this->id;
    }

    public function getDisplayName(): string
    {
        return $this->displayName;
    }

    public function jsonSerialize(): array
    {
        $json = parent::jsonSerialize();
        $json['id'] = base64_encode($this->id);
        $json['displayName'] = $this->displayName;

        return $json;
    }
}
