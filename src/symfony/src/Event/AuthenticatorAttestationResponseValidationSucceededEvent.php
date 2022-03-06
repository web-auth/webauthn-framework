<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Event;

use Psr\Http\Message\ServerRequestInterface;
use Symfony\Contracts\EventDispatcher\Event;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialSource;

class AuthenticatorAttestationResponseValidationSucceededEvent extends Event
{
    public function __construct(
        private AuthenticatorAttestationResponse $authenticatorAttestationResponse,
        private PublicKeyCredentialCreationOptions $publicKeyCredentialCreationOptions,
        private ServerRequestInterface $request,
        private PublicKeyCredentialSource $publicKeyCredentialSource
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

    public function getPublicKeyCredentialSource(): PublicKeyCredentialSource
    {
        return $this->publicKeyCredentialSource;
    }
}
