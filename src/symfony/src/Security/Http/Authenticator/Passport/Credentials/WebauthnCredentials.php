<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Security\Http\Authenticator\Passport\Credentials;

use Symfony\Component\Security\Http\Authenticator\Passport\Credentials\CredentialsInterface;
use Webauthn\AuthenticatorResponse;
use Webauthn\PublicKeyCredentialOptions;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\PublicKeyCredentialUserEntity;

/**
 * @final
 */
class WebauthnCredentials implements CredentialsInterface
{
    public function __construct(
        private AuthenticatorResponse $authenticatorResponse,
        private PublicKeyCredentialOptions $publicKeyCredentialOptions,
        private null|PublicKeyCredentialUserEntity $publicKeyCredentialUserEntity,
        private PublicKeyCredentialSource $publicKeyCredentialSource,
        private string $firewallName,
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
