<?php

declare(strict_types=1);

namespace Webauthn;

use Webauthn\AttestationStatement\AttestationObject;
use Webauthn\AuthenticationExtensions\AuthenticationExtensions;

/**
 * @see https://www.w3.org/TR/webauthn/#authenticatorassertionresponse
 */
class AuthenticatorAssertionResponse extends AuthenticatorResponse
{
    public function __construct(
        CollectedClientData $clientDataJSON,
        public readonly AuthenticatorData $authenticatorData,
        public readonly string $signature,
        public readonly ?string $userHandle,
        public readonly null|AttestationObject $attestationObject = null,
        null|AuthenticationExtensions $clientExtensionResults = null,
    ) {
        parent::__construct($clientDataJSON, $clientExtensionResults);
    }

    public static function create(
        CollectedClientData $clientDataJSON,
        AuthenticatorData $authenticatorData,
        string $signature,
        ?string $userHandle = null,
        null|AttestationObject $attestationObject = null,
        null|AuthenticationExtensions $clientExtensionResults = null,
    ): self {
        return new self(
            $clientDataJSON,
            $authenticatorData,
            $signature,
            $userHandle,
            $attestationObject,
            $clientExtensionResults
        );
    }
}
