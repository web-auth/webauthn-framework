<?php

declare(strict_types=1);

namespace Webauthn;

use Assert\Assertion;
use JetBrains\PhpStorm\ArrayShape;

class PublicKeyCredentialRpEntity extends PublicKeyCredentialEntity
{
    
    public function __construct(string $name, protected ?string $id = null, ?string $icon = null)
    {
        parent::__construct($name, $icon);
    }

    
    public static function create(string $name, ?string $id = null, ?string $icon = null): self
    {
        return new self($name, $id, $icon);
    }

    
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

    
    #[ArrayShape(['name' => 'string', 'icon' => 'null|string', 'id' => 'null|string'])]
    public function jsonSerialize(): array
    {
        $json = parent::jsonSerialize();
        if (null !== $this->id) {
            $json['id'] = $this->id;
        }

        return $json;
    }
}
