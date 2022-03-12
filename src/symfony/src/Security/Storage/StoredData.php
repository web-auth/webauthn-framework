<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Security\Storage;

use Webauthn\PublicKeyCredentialOptions;
use Webauthn\PublicKeyCredentialUserEntity;

class StoredData
{
    
    public function __construct(private PublicKeyCredentialOptions $publicKeyCredentialOptions, private ?PublicKeyCredentialUserEntity $publicKeyCredentialUserEntity)
    {
    }

    
    public function getPublicKeyCredentialOptions(): PublicKeyCredentialOptions
    {
        return $this->publicKeyCredentialOptions;
    }

    
    public function getPublicKeyCredentialUserEntity(): ?PublicKeyCredentialUserEntity
    {
        return $this->publicKeyCredentialUserEntity;
    }
}
