<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2021 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Webauthn\Bundle\Security\Storage;

use Webauthn\PublicKeyCredentialOptions;
use Webauthn\PublicKeyCredentialUserEntity;

class StoredData
{
    /**
     * @var PublicKeyCredentialOptions
     */
    private $publicKeyCredentialOptions;

    /**
     * @var PublicKeyCredentialUserEntity|null
     */
    private $publicKeyCredentialUserEntity;

    public function __construct(PublicKeyCredentialOptions $publicKeyCredentialOptions, ?PublicKeyCredentialUserEntity $publicKeyCredentialUserEntity)
    {
        $this->publicKeyCredentialOptions = $publicKeyCredentialOptions;
        $this->publicKeyCredentialUserEntity = $publicKeyCredentialUserEntity;
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
