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

use Psr\Http\Message\ServerRequestInterface;
use Symfony\Contracts\EventDispatcher\Event;
use Throwable;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\PublicKeyCredentialRequestOptions;

class AuthenticatorAssertionResponseValidationFailedEvent extends Event
{
    /**
     * @var string
     */
    private $credentialId;

    /**
     * @var AuthenticatorAssertionResponse
     */
    private $authenticatorAssertionResponse;

    /**
     * @var PublicKeyCredentialRequestOptions
     */
    private $publicKeyCredentialRequestOptions;

    /**
     * @var ServerRequestInterface
     */
    private $request;

    /**
     * @var string|null
     */
    private $userHandle;

    /**
     * @var Throwable
     */
    private $throwable;

    public function __construct(string $credentialId, AuthenticatorAssertionResponse $authenticatorAssertionResponse, PublicKeyCredentialRequestOptions $publicKeyCredentialRequestOptions, ServerRequestInterface $request, ?string $userHandle, Throwable $throwable)
    {
        $this->credentialId = $credentialId;
        $this->authenticatorAssertionResponse = $authenticatorAssertionResponse;
        $this->publicKeyCredentialRequestOptions = $publicKeyCredentialRequestOptions;
        $this->request = $request;
        $this->userHandle = $userHandle;
        $this->throwable = $throwable;
    }

    public function getCredentialId(): string
    {
        return $this->credentialId;
    }

    public function getAuthenticatorAssertionResponse(): AuthenticatorAssertionResponse
    {
        return $this->authenticatorAssertionResponse;
    }

    public function getPublicKeyCredentialRequestOptions(): PublicKeyCredentialRequestOptions
    {
        return $this->publicKeyCredentialRequestOptions;
    }

    public function getRequest(): ServerRequestInterface
    {
        return $this->request;
    }

    public function getUserHandle(): ?string
    {
        return $this->userHandle;
    }

    public function getThrowable(): Throwable
    {
        return $this->throwable;
    }
}
