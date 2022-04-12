<?php

declare(strict_types=1);

namespace Webauthn;

use Assert\Assertion;
use const JSON_THROW_ON_ERROR;
use JsonSerializable;

class PublicKeyCredentialParameters implements JsonSerializable
{
    public function __construct(
        private readonly string $type,
        private readonly int $alg
    ) {
    }

    public static function create(string $type, int $alg): self
    {
        return new self($type, $alg);
    }

    public function getType(): string
    {
        return $this->type;
    }

    public function getAlg(): int
    {
        return $this->alg;
    }

    public static function createFromString(string $data): self
    {
        $data = json_decode($data, true, 512, JSON_THROW_ON_ERROR);
        Assertion::isArray($data, 'Invalid data');

        return self::createFromArray($data);
    }

    /**
     * @param mixed[] $json
     */
    public static function createFromArray(array $json): self
    {
        Assertion::keyExists($json, 'type', 'Invalid input. "type" is missing.');
        Assertion::string($json['type'], 'Invalid input. "type" is not a string.');
        Assertion::keyExists($json, 'alg', 'Invalid input. "alg" is missing.');
        Assertion::integer($json['alg'], 'Invalid input. "alg" is not an integer.');

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
