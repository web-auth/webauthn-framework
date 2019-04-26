<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2019 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Webauthn\Bundle\Security\Storage;

use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialUserEntity;

class StoredData
{
    /**
     * @var PublicKeyCredentialRequestOptions
     */
    private $publicKeyCredentialRequestOptions;

    /**
     * @var PublicKeyCredentialUserEntity
     */
    private $publicKeyCredentialUserEntity;

    public function __construct(PublicKeyCredentialRequestOptions $publicKeyCredentialRequestOptions, PublicKeyCredentialUserEntity $publicKeyCredentialUserEntity)
    {
        $this->publicKeyCredentialRequestOptions = $publicKeyCredentialRequestOptions;
        $this->publicKeyCredentialUserEntity = $publicKeyCredentialUserEntity;
    }

    public function getPublicKeyCredentialRequestOptions(): PublicKeyCredentialRequestOptions
    {
        return $this->publicKeyCredentialRequestOptions;
    }

    public function getPublicKeyCredentialUserEntity(): PublicKeyCredentialUserEntity
    {
        return $this->publicKeyCredentialUserEntity;
    }
}
