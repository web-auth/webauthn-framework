<?php

declare(strict_types=1);

namespace Webauthn\Event;

use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialSource;

readonly class AuthenticatorAttestationResponseValidationSucceededEvent
{
    public function __construct(
        public AuthenticatorAttestationResponse $authenticatorAttestationResponse,
        public PublicKeyCredentialCreationOptions $publicKeyCredentialCreationOptions,
        public string $host,
        public PublicKeyCredentialSource $publicKeyCredentialSource
    ) {
    }
}
