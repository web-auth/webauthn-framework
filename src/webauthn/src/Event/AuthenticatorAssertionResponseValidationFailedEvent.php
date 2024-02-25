<?php

declare(strict_types=1);

namespace Webauthn\Event;

use Throwable;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialSource;

readonly class AuthenticatorAssertionResponseValidationFailedEvent
{
    public function __construct(
        public PublicKeyCredentialSource $credentialSource,
        public AuthenticatorAssertionResponse $authenticatorAssertionResponse,
        public PublicKeyCredentialRequestOptions $publicKeyCredentialRequestOptions,
        public string $host,
        public ?string $userHandle,
        public Throwable $throwable
    ) {
    }
}
