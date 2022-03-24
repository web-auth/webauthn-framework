<?php

declare(strict_types=1);

namespace Webauthn;

use Assert\Assertion;
use const JSON_THROW_ON_ERROR;
use ParagonIE\ConstantTime\Base64;
use ParagonIE\ConstantTime\Base64UrlSafe;

class PublicKeyCredentialUserEntity extends PublicKeyCredentialEntity
{
    protected string $id;

    public function __construct(
        string $name,
        string $id,
        protected string $displayName,
        ?string $icon = null
    ) {
        parent::__construct($name, $icon);
        Assertion::maxLength($id, 64, 'User ID max length is 64 bytes', 'id', '8bit');
        $this->id = $id;
    }

    public static function create(string $name, string $id, string $displayName, ?string $icon = null): self
    {
        return new self($name, $id, $displayName, $icon);
    }

    public function getId(): string
    {
        return $this->id;
    }

    public function getDisplayName(): string
    {
        return $this->displayName;
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
        Assertion::keyExists($json, 'name', 'Invalid input. "name" is missing.');
        Assertion::keyExists($json, 'id', 'Invalid input. "id" is missing.');
        Assertion::keyExists($json, 'displayName', 'Invalid input. "displayName" is missing.');
        $id = Base64::decode($json['id'], true);

        return new self($json['name'], $id, $json['displayName'], $json['icon'] ?? null);
    }

    /**
     * @return mixed[]
     */
    public function jsonSerialize(): array
    {
        $json = parent::jsonSerialize();
        $json['id'] = Base64UrlSafe::encodeUnpadded($this->id);
        $json['displayName'] = $this->displayName;

        return $json;
    }
}
