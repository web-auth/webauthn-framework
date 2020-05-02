<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2020 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Webauthn\Bundle\Event;

use Psr\Http\Message\ServerRequestInterface;
use Symfony\Contracts\EventDispatcher\Event;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialSource;

class AuthenticatorAttestationResponseValidationSucceededEvent extends Event
{
    /**
     * @var AuthenticatorAttestationResponse
     */
    private $authenticatorAttestationResponse;

    /**
     * @var PublicKeyCredentialCreationOptions
     */
    private $publicKeyCredentialCreationOptions;

    /**
     * @var ServerRequestInterface
     */
    private $request;

    /**
     * @var PublicKeyCredentialSource
     */
    private $publicKeyCredentialSource;

    public function __construct(AuthenticatorAttestationResponse $authenticatorAttestationResponse, PublicKeyCredentialCreationOptions $publicKeyCredentialCreationOptions, ServerRequestInterface $request, PublicKeyCredentialSource $publicKeyCredentialSource)
    {
        $this->authenticatorAttestationResponse = $authenticatorAttestationResponse;
        $this->publicKeyCredentialCreationOptions = $publicKeyCredentialCreationOptions;
        $this->request = $request;
        $this->publicKeyCredentialSource = $publicKeyCredentialSource;
    }

    public function getAuthenticatorAttestationResponse(): AuthenticatorAttestationResponse
    {
        return $this->authenticatorAttestationResponse;
    }

    public function getPublicKeyCredentialCreationOptions(): PublicKeyCredentialCreationOptions
    {
        return $this->publicKeyCredentialCreationOptions;
    }

    public function getRequest(): ServerRequestInterface
    {
        return $this->request;
    }

    public function getPublicKeyCredentialSource(): PublicKeyCredentialSource
    {
        return $this->publicKeyCredentialSource;
    }
}
