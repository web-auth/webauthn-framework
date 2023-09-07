<?php

declare(strict_types=1);

namespace Webauthn;

use JsonSerializable;
use Webauthn\Exception\InvalidDataException;
use function array_key_exists;
use const JSON_THROW_ON_ERROR;

class PublicKeyCredentialParameters implements JsonSerializable
{
    public function __construct(
        public readonly string $type,
        public readonly int $alg
    ) {
    }

    public static function create(string $type, int $alg): self
    {
        return new self($type, $alg);
    }

    /**
     * @deprecated since 4.7.0. Please use the property directly.
     */
    public function getType(): string
    {
        return $this->type;
    }

    /**
     * @deprecated since 4.7.0. Please use the property directly.
     */
    public function getAlg(): int
    {
        return $this->alg;
    }

    public static function createFromString(string $data): self
    {
        $data = json_decode($data, true, flags: JSON_THROW_ON_ERROR);

        return self::createFromArray($data);
    }

    /**
     * @param mixed[] $json
     */
    public static function createFromArray(array $json): self
    {
        array_key_exists('type', $json) || throw InvalidDataException::create(
            $json,
            'Invalid input. "type" is missing.'
        );
        array_key_exists('alg', $json) || throw InvalidDataException::create(
            $json,
            'Invalid input. "alg" is missing.'
        );

        return new self($json['type'], $json['alg']);
    }

    /**
     * @return mixed[]
     */
    public function jsonSerialize(): array
    {
        return [
            'type' => $this->type,
            'alg' => $this->alg,
        ];
    }
}
