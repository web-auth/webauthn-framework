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

use JetBrains\PhpStorm\Pure;
use Psr\Http\Message\ServerRequestInterface;
use Symfony\Contracts\EventDispatcher\Event;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialSource;

class AuthenticatorAttestationResponseValidationSucceededEvent extends Event
{
    #[Pure]
    public function __construct(private AuthenticatorAttestationResponse $authenticatorAttestationResponse, private PublicKeyCredentialCreationOptions $publicKeyCredentialCreationOptions, private ServerRequestInterface $request, private PublicKeyCredentialSource $publicKeyCredentialSource)
    {
    }

    #[Pure]
    public function getAuthenticatorAttestationResponse(): AuthenticatorAttestationResponse
    {
        return $this->authenticatorAttestationResponse;
    }

    #[Pure]
    public function getPublicKeyCredentialCreationOptions(): PublicKeyCredentialCreationOptions
    {
        return $this->publicKeyCredentialCreationOptions;
    }

    #[Pure]
    public function getRequest(): ServerRequestInterface
    {
        return $this->request;
    }

    #[Pure]
    public function getPublicKeyCredentialSource(): PublicKeyCredentialSource
    {
        return $this->publicKeyCredentialSource;
    }
}
