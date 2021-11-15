<?php

declare(strict_types=1);

namespace Webauthn;

use JsonSerializable;

abstract class PublicKeyCredentialEntity implements JsonSerializable
{
    public function __construct(
        protected string $name,
        protected ?string $icon
    ) {
    }

    public function getName(): string
    {
        return $this->name;
    }

    public function getIcon(): ?string
    {
        return $this->icon;
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
