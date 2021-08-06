<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Security\Storage;

use JetBrains\PhpStorm\Pure;
use Webauthn\PublicKeyCredentialOptions;
use Webauthn\PublicKeyCredentialUserEntity;

class StoredData
{
    #[Pure]
    public function __construct(private PublicKeyCredentialOptions $publicKeyCredentialOptions, private ?PublicKeyCredentialUserEntity $publicKeyCredentialUserEntity)
    {
    }

    #[Pure]
    public function getPublicKeyCredentialOptions(): PublicKeyCredentialOptions
    {
        return $this->publicKeyCredentialOptions;
    }

    #[Pure]
    public function getPublicKeyCredentialUserEntity(): ?PublicKeyCredentialUserEntity
    {
        return $this->publicKeyCredentialUserEntity;
    }
}
