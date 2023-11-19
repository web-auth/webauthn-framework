<?php

declare(strict_types=1);

namespace Webauthn\Event;

use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialSource;

class AuthenticatorAttestationResponseValidationSucceededEvent
{
    public function __construct(
        public readonly AuthenticatorAttestationResponse $authenticatorAttestationResponse,
        public readonly PublicKeyCredentialCreationOptions $publicKeyCredentialCreationOptions,
        public readonly string $host,
        public readonly PublicKeyCredentialSource $publicKeyCredentialSource
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

    public function getPublicKeyCredentialSource(): PublicKeyCredentialSource
    {
        return $this->publicKeyCredentialSource;
    }
}
