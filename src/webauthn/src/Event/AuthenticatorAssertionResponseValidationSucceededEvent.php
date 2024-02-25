<?php

declare(strict_types=1);

namespace Webauthn\Event;

use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialSource;

class AuthenticatorAssertionResponseValidationSucceededEvent
{
    public function __construct(
        public readonly AuthenticatorAssertionResponse $authenticatorAssertionResponse,
        public readonly PublicKeyCredentialRequestOptions $publicKeyCredentialRequestOptions,
        public readonly string $host,
        public readonly ?string $userHandle,
        public readonly PublicKeyCredentialSource $publicKeyCredentialSource
    ) {
    }
}
