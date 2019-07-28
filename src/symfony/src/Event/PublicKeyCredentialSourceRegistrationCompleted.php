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

namespace Webauthn\Bundle\Event;

use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialSource;

final class PublicKeyCredentialSourceRegistrationCompleted
{
    /**
     * @var PublicKeyCredentialCreationOptions
     */
    private $publicKeyCredentialCreationOptions;

    /**
     * @var AuthenticatorAttestationResponse
     */
    private $authenticatorAttestationResponse;

    /**
     * @var PublicKeyCredentialSource
     */
    private $publicKeyCredentialSource;

    /**
     * @var string
     */
    private $providerKey;

    public function __construct(string $providerKey, PublicKeyCredentialCreationOptions $publicKeyCredentialCreationOptions, AuthenticatorAttestationResponse $authenticatorAttestationResponse, PublicKeyCredentialSource $publicKeyCredentialSource)
    {
        $this->providerKey = $providerKey;
        $this->publicKeyCredentialSource = $publicKeyCredentialSource;
        $this->publicKeyCredentialCreationOptions = $publicKeyCredentialCreationOptions;
        $this->authenticatorAttestationResponse = $authenticatorAttestationResponse;
    }

    public function getProviderKey(): string
    {
        return $this->providerKey;
    }

    public function getPublicKeyCredentialCreationOptions(): PublicKeyCredentialCreationOptions
    {
        return $this->publicKeyCredentialCreationOptions;
    }

    public function getAuthenticatorAttestationResponse(): AuthenticatorAttestationResponse
    {
        return $this->authenticatorAttestationResponse;
    }

    public function getPublicKeyCredentialSource(): PublicKeyCredentialSource
    {
        return $this->publicKeyCredentialSource;
    }
}
