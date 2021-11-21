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

namespace Webauthn\Bundle\Event;

use Psr\Http\Message\ServerRequestInterface;
use Symfony\Contracts\EventDispatcher\Event;
use Throwable;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\PublicKeyCredentialCreationOptions;

class AuthenticatorAttestationResponseValidationFailedEvent extends Event
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
     * @var Throwable
     */
    private $throwable;

    public function __construct(AuthenticatorAttestationResponse $authenticatorAttestationResponse, PublicKeyCredentialCreationOptions $publicKeyCredentialCreationOptions, ServerRequestInterface $request, Throwable $throwable)
    {
        $this->authenticatorAttestationResponse = $authenticatorAttestationResponse;
        $this->publicKeyCredentialCreationOptions = $publicKeyCredentialCreationOptions;
        $this->request = $request;
        $this->throwable = $throwable;
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

    public function getThrowable(): Throwable
    {
        return $this->throwable;
    }
}
