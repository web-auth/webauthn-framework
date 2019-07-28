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

use RuntimeException;
use Webauthn\PublicKeyCredentialOptions;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialUserEntity;

class StoredData
{
    /**
     * @var PublicKeyCredentialOptions
     */
    private $publicKeyCredentialOptions;

    /**
     * @var PublicKeyCredentialUserEntity
     */
    private $publicKeyCredentialUserEntity;

    public function __construct(PublicKeyCredentialOptions $publicKeyCredentialOptions, PublicKeyCredentialUserEntity $publicKeyCredentialUserEntity)
    {
        $this->publicKeyCredentialOptions = $publicKeyCredentialOptions;
        $this->publicKeyCredentialUserEntity = $publicKeyCredentialUserEntity;
    }

    /**
     * @deprecated Will be removed in v3.0. Please use getPublicKeyCredentialOptions() instead
     */
    public function getPublicKeyCredentialRequestOptions(): PublicKeyCredentialRequestOptions
    {
        if (!$this->publicKeyCredentialOptions instanceof PublicKeyCredentialRequestOptions) {
            throw new RuntimeException('Inconsistent data');
        }

        return $this->publicKeyCredentialOptions;
    }

    public function getPublicKeyCredentialOptions(): PublicKeyCredentialOptions
    {
        return $this->publicKeyCredentialOptions;
    }

    public function getPublicKeyCredentialUserEntity(): PublicKeyCredentialUserEntity
    {
        return $this->publicKeyCredentialUserEntity;
    }
}
