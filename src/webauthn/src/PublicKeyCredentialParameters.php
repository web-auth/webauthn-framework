<?php

declare(strict_types=1);

namespace Webauthn;

use JsonSerializable;

class PublicKeyCredentialParameters implements JsonSerializable
{
    /**
     * @private
     */
    public function __construct(
        public readonly string $type,
        public readonly int $alg
    ) {
    }

    public static function create(string $type, int $alg): self
    {
        return new self($type, $alg);
    }

    public static function createPk(int $alg): self
    {
        return self::create(PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY, $alg);
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
