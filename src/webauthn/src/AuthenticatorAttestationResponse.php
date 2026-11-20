<?php

declare(strict_types=1);

namespace Webauthn;

use Webauthn\AttestationStatement\AttestationObject;
use Webauthn\AuthenticationExtensions\AuthenticationExtensions;

/**
 * @see https://www.w3.org/TR/webauthn/#authenticatorattestationresponse
 */
class AuthenticatorAttestationResponse extends AuthenticatorResponse
{
    /**
     * @param string[] $transports
     */
    public function __construct(
        CollectedClientData $clientDataJSON,
        public readonly AttestationObject $attestationObject,
        public readonly array $transports = [],
        null|AuthenticationExtensions $clientExtensionResults = null,
    ) {
        parent::__construct($clientDataJSON, $clientExtensionResults);
    }

    /**
     * @param string[] $transports
     */
    public static function create(
        CollectedClientData $clientDataJSON,
        AttestationObject $attestationObject,
        array $transports = [],
        null|AuthenticationExtensions $clientExtensionResults = null,
    ): self {
        return new self($clientDataJSON, $attestationObject, $transports, $clientExtensionResults);
    }
}
