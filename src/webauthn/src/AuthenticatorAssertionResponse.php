<?php

declare(strict_types=1);

namespace Webauthn;

/**
 * @see https://www.w3.org/TR/webauthn/#authenticatorassertionresponse
 */
class AuthenticatorAssertionResponse extends AuthenticatorResponse
{
    public function __construct(
        CollectedClientData $clientDataJSON,
        public readonly AuthenticatorData $authenticatorData,
        public readonly string $signature,
        public readonly ?string $userHandle
    ) {
        parent::__construct($clientDataJSON);
    }

    /**
     * @deprecated since 4.7.0. Please use the property directly.
     */
    public function getAuthenticatorData(): AuthenticatorData
    {
        return $this->authenticatorData;
    }

    /**
     * @deprecated since 4.7.0. Please use the property directly.
     */
    public function getSignature(): string
    {
        return $this->signature;
    }

    /**
     * @deprecated since 4.7.0. Please use the property directly.
     */
    public function getUserHandle(): ?string
    {
        return $this->userHandle;
    }
}
