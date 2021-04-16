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
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialSource;

class AuthenticatorAssertionResponseValidationSucceededEvent extends Event
{
    #[Pure]
    public function __construct(private string $credentialId, private AuthenticatorAssertionResponse $authenticatorAssertionResponse, private PublicKeyCredentialRequestOptions $publicKeyCredentialRequestOptions, private ServerRequestInterface $request, private ?string $userHandle, private PublicKeyCredentialSource $publicKeyCredentialSource)
    {
    }

    #[Pure]
    public function getCredentialId(): string
    {
        return $this->credentialId;
    }

    #[Pure]
    public function getAuthenticatorAssertionResponse(): AuthenticatorAssertionResponse
    {
        return $this->authenticatorAssertionResponse;
    }

    #[Pure]
    public function getPublicKeyCredentialRequestOptions(): PublicKeyCredentialRequestOptions
    {
        return $this->publicKeyCredentialRequestOptions;
    }

    #[Pure]
    public function getRequest(): ServerRequestInterface
    {
        return $this->request;
    }

    #[Pure]
    public function getUserHandle(): ?string
    {
        return $this->userHandle;
    }

    #[Pure]
    public function getPublicKeyCredentialSource(): PublicKeyCredentialSource
    {
        return $this->publicKeyCredentialSource;
    }
}
