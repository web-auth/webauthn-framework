<?php

declare(strict_types=1);

namespace Webauthn;

use function array_key_exists;
use Webauthn\Exception\InvalidDataException;

class PublicKeyCredentialRpEntity extends PublicKeyCredentialEntity
{
    public function __construct(
        string $name,
        protected ?string $id = null,
        ?string $icon = null
    ) {
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

    /**
     * @param mixed[] $json
     */
    public static function createFromArray(array $json): self
    {
        array_key_exists('name', $json) || throw InvalidDataException::create(
            $json,
            'Invalid input. "name" is missing.'
        );

        return new self($json['name'], $json['id'] ?? null, $json['icon'] ?? null);
    }

    /**
     * @return mixed[]
     */
    public function jsonSerialize(): array
    {
        $json = parent::jsonSerialize();
        if ($this->id !== null) {
            $json['id'] = $this->id;
        }

        return $json;
    }
}
