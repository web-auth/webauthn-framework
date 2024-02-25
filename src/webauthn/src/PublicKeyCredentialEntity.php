<?php

declare(strict_types=1);

namespace Webauthn;

use JsonSerializable;

abstract class PublicKeyCredentialEntity implements JsonSerializable
{
    public function __construct(
        public readonly string $name,
        public readonly ?string $icon
    ) {
    }

    /**
     * @return mixed[]
     */
    public function jsonSerialize(): array
    {
        $json = [
            'name' => $this->name,
        ];
        if ($this->icon !== null) {
            $json['icon'] = $this->icon;
        }

        return $json;
    }
}
