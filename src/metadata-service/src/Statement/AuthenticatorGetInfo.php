<?php

declare(strict_types=1);

namespace Webauthn\MetadataService\Statement;

use function is_string;
use JsonSerializable;

class AuthenticatorGetInfo implements JsonSerializable
{
    /**
     * @var string[]
     */
    private array $info = [];

    /**
     * @param array<string, mixed> $data
     */
    public static function create(array $data = []): self
    {
        $object = new self();
        foreach ($data as $k => $v) {
            if (is_string($k)) {
                $object->add($k, $v);
            }
        }

        return $object;
    }

    public function add(string $key, mixed $value): self
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
