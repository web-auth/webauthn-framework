<?php

declare(strict_types=1);

namespace Webauthn;

use JetBrains\PhpStorm\ArrayShape;
use JetBrains\PhpStorm\Pure;
use JsonSerializable;

abstract class PublicKeyCredentialEntity implements JsonSerializable
{
    #[Pure]
    public function __construct(protected string $name, protected ?string $icon)
    {
    }

    #[Pure]
    public function getName(): string
    {
        return $this->name;
    }

    #[Pure]
    public function getIcon(): ?string
    {
        return $this->icon;
    }

    #[Pure]
    #[ArrayShape(['name' => 'string', 'icon' => 'null|string'])]
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
