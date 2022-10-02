<?php

declare(strict_types=1);

namespace Webauthn\Event;

use Psr\Http\Message\ServerRequestInterface;
use Throwable;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\PublicKeyCredentialCreationOptions;

class AuthenticatorAttestationResponseValidationFailedEvent
{
    public function __construct(
        private readonly AuthenticatorAttestationResponse $authenticatorAttestationResponse,
        private readonly PublicKeyCredentialCreationOptions $publicKeyCredentialCreationOptions,
        private readonly ServerRequestInterface $request,
        private readonly Throwable $throwable
    ) {
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
