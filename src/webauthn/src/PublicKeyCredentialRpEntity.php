<?php

declare(strict_types=1);

namespace Webauthn;

class PublicKeyCredentialRpEntity extends PublicKeyCredentialEntity
{
    public function __construct(
        string $name = '',
        public readonly ?string $id = null,
        ?string $icon = null
    ) {

        parent::__construct($name, $icon);
    }

    public static function create(string $name = '', ?string $id = null, ?string $icon = null): self
    {
        return new self($name, $id, $icon);
    }
}
