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

class PublicKeyCredentialUserEntity extends PublicKeyCredentialEntity
{
    /**
     * @var string
     */
    protected $id;

    /**
     * @var string
     */
    protected $displayName;

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

    /**
     * @deprecated will be removed in v2.0. Use "createFromArray" instead
     */
    public static function createFromJson(array $json): self
    {
        return self::createFromArray($json);
    }

    public static function createFromArray(array $json): self
    {
        Assertion::keyExists($json, 'name', 'Invalid input. "name" is missing.');
        Assertion::keyExists($json, 'id', 'Invalid input. "id" is missing.');
        Assertion::keyExists($json, 'displayName', 'Invalid input. "displayName" is missing.');

        return new self(
            $json['name'],
            \Safe\base64_decode($json['id'], true),
            $json['displayName'],
            $json['icon'] ?? null
        );
    }

    public function jsonSerialize(): array
    {
        $json = parent::jsonSerialize();
        $json['id'] = base64_encode($this->id);
        $json['displayName'] = $this->displayName;

        return $json;
    }
}
