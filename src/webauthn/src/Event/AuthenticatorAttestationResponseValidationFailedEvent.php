<?php

declare(strict_types=1);

namespace Webauthn\Event;

use Throwable;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\PublicKeyCredentialCreationOptions;

class AuthenticatorAttestationResponseValidationFailedEvent
{
    public function __construct(
        public readonly AuthenticatorAttestationResponse $authenticatorAttestationResponse,
        public readonly PublicKeyCredentialCreationOptions $publicKeyCredentialCreationOptions,
        public readonly string $host,
        public readonly Throwable $throwable
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

    public function getThrowable(): Throwable
    {
        return $this->throwable;
    }
}
