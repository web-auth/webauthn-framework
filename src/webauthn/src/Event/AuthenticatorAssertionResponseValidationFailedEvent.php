<?php

declare(strict_types=1);

namespace Webauthn\Event;

use Throwable;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialSource;

class AuthenticatorAssertionResponseValidationFailedEvent
{
    public function __construct(
        public readonly PublicKeyCredentialSource $publicKeyCredentialSource,
        public readonly AuthenticatorAssertionResponse $authenticatorAssertionResponse,
        public readonly PublicKeyCredentialRequestOptions $publicKeyCredentialRequestOptions,
        public readonly string $host,
        public readonly ?string $userHandle,
        public readonly Throwable $throwable
    ) {
    }

    public function getCredential(): PublicKeyCredentialSource
    {
        return $this->publicKeyCredentialSource;
    }

    public function getAuthenticatorAssertionResponse(): AuthenticatorAssertionResponse
    {
        return $this->authenticatorAssertionResponse;
    }

    public function getPublicKeyCredentialRequestOptions(): PublicKeyCredentialRequestOptions
    {
        return $this->publicKeyCredentialRequestOptions;
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
