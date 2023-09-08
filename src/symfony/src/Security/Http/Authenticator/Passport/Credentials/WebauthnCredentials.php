<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Security\Http\Authenticator\Passport\Credentials;

use Symfony\Component\Security\Http\Authenticator\Passport\Credentials\CredentialsInterface;
use Webauthn\AuthenticatorResponse;
use Webauthn\PublicKeyCredentialOptions;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\PublicKeyCredentialUserEntity;

class WebauthnCredentials implements CredentialsInterface
{
    public function __construct(
        private readonly AuthenticatorResponse $authenticatorResponse,
        private readonly PublicKeyCredentialOptions $publicKeyCredentialOptions,
        private readonly PublicKeyCredentialUserEntity $publicKeyCredentialUserEntity,
        private readonly PublicKeyCredentialSource $publicKeyCredentialSource,
        private readonly string $firewallName,
    ) {
    }

    public function getAuthenticatorResponse(): AuthenticatorResponse
    {
        return $this->authenticatorResponse;
    }

    public function getPublicKeyCredentialOptions(): PublicKeyCredentialOptions
    {
        return $this->publicKeyCredentialOptions;
    }

    public function getPublicKeyCredentialUserEntity(): ?PublicKeyCredentialUserEntity
    {
        return $this->publicKeyCredentialUserEntity;
    }

    public function getPublicKeyCredentialSource(): PublicKeyCredentialSource
    {
        return $this->publicKeyCredentialSource;
    }

    public function getFirewallName(): string
    {
        return $this->firewallName;
    }

    public function isResolved(): bool
    {
        return true;
    }
}
