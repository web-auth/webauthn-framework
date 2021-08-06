<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Event;

use JetBrains\PhpStorm\Pure;
use Psr\Http\Message\ServerRequestInterface;
use Symfony\Contracts\EventDispatcher\Event;
use Throwable;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\PublicKeyCredentialCreationOptions;

class AuthenticatorAttestationResponseValidationFailedEvent extends Event
{
    #[Pure]
    public function __construct(private AuthenticatorAttestationResponse $authenticatorAttestationResponse, private PublicKeyCredentialCreationOptions $publicKeyCredentialCreationOptions, private ServerRequestInterface $request, private Throwable $throwable)
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
    public function getThrowable(): Throwable
    {
        return $this->throwable;
    }
}
