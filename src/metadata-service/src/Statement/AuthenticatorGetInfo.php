<?php

declare(strict_types=1);

namespace Webauthn\MetadataService\Statement;

use JsonSerializable;

/**
 * @final
 */
class AuthenticatorGetInfo implements JsonSerializable
{
    /**
     * @var string[]
     */
    private array $info = [];

    /**
     * @param array<string|int, mixed> $data
     */
    public static function create(array $data = []): self
    {
        $object = new self();
        foreach ($data as $k => $v) {
            $object->add($k, $v);
        }

        return $object;
    }

    public function add(string|int $key, mixed $value): self
    {
        $this->info[$key] = $value;

        return $this;
    }

    /**
     * @return string[]
     */
    public function jsonSerialize(): array
    {
        return $this->info;
    }
}
