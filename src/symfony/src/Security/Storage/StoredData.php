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

use Assert\Assertion;
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
     * @var PublicKeyCredentialUserEntity|null
     */
    private $publicKeyCredentialUserEntity;

    public function __construct(PublicKeyCredentialOptions $publicKeyCredentialOptions, ?PublicKeyCredentialUserEntity $publicKeyCredentialUserEntity)
    {
        $this->publicKeyCredentialOptions = $publicKeyCredentialOptions;
        $this->publicKeyCredentialUserEntity = $publicKeyCredentialUserEntity;
    }

    /**
     * @deprecated Will be removed in v3.0. Please use getPublicKeyCredentialOptions instead
     */
    public function getPublicKeyCredentialRequestOptions(): PublicKeyCredentialOptions
    {
        Assertion::isInstanceOf($this->publicKeyCredentialOptions, PublicKeyCredentialRequestOptions::class, sprintf('The object is not an instance of Webauthn\$this->publicKeyCredentialOptions. Got "%s" instead', \get_class($this->publicKeyCredentialOptions)));

        return $this->publicKeyCredentialOptions;
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
