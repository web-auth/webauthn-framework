<?php

declare(strict_types=1);

namespace Webauthn;

use JetBrains\PhpStorm\ArrayShape;
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
