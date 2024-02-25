<?php

declare(strict_types=1);

namespace Webauthn;

use ParagonIE\ConstantTime\Base64UrlSafe;
use Webauthn\Exception\InvalidDataException;

class PublicKeyCredentialUserEntity extends PublicKeyCredentialEntity
{
    public readonly string $id;

    public function __construct(
        string $name,
        string $id,
        public readonly string $displayName,
        ?string $icon = null
    ) {
        parent::__construct($name, $icon);
        mb_strlen($id, '8bit') <= 64 || throw InvalidDataException::create($id, 'User ID max length is 64 bytes');
        $this->id = $id;
    }

    public static function create(string $name, string $id, string $displayName, ?string $icon = null): self
    {
        return new self($name, $id, $displayName, $icon);
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
