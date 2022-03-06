<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Security\Http\Authenticator\Passport\Credentials;

use Symfony\Component\Security\Http\Authenticator\Passport\Credentials\CredentialsInterface;
use Webauthn\Bundle\Security\Authentication\Token\WebauthnTokenInterface;

/**
 * @final
 */
class WebauthnCredentials implements CredentialsInterface
{
    private bool $resolved = false;

    public function __construct(
        private WebauthnTokenInterface $webauthnToken,
    ) {
    }

    public function getWebauthnToken(): WebauthnTokenInterface
    {
        return $this->webauthnToken;
    }

    public function isResolved(): bool
    {
        return $this->resolved;
    }
}
