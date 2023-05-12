<?php

declare(strict_types=1);

namespace Webauthn;

use Webauthn\Util\Base64;

/**
 * @see https://www.w3.org/TR/webauthn/#authenticatorassertionresponse
 */
class AuthenticatorAssertionResponse extends AuthenticatorResponse
{
    public function __construct(
        CollectedClientData $clientDataJSON,
        private readonly AuthenticatorData $authenticatorData,
        private readonly string $signature,
        private readonly ?string $userHandle
    ) {
        parent::__construct($clientDataJSON);
    }

    public function getAuthenticatorData(): AuthenticatorData
    {
        return $this->authenticatorData;
    }

    public function getSignature(): string
    {
        return $this->signature;
    }

    public function getUserHandle(): ?string
    {
        if ($this->userHandle === null || $this->userHandle === '') {
            return $this->userHandle;
        }

        return Base64::decode($this->userHandle);
    }
}
