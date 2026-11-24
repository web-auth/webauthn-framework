<?php

declare(strict_types=1);

namespace Webauthn;

use Webauthn\AuthenticationExtensions\AuthenticationExtensions;

/**
 * @see https://www.w3.org/TR/webauthn/#authenticatorresponse
 */
abstract class AuthenticatorResponse
{
    /**
     * `$clientExtensionResults` are the client extension outputs of the credential, as returned by
     * `getClientExtensionResults()`. They belong to the credential rather than to the authenticator response, but the
     * ceremony steps only receive the response, so {@see Denormalizer\PublicKeyCredentialDenormalizer} attaches them
     * here. They are `null` when the client did not send them and, unlike the authenticator data, they are not signed
     * by the authenticator.
     */
    public function __construct(
        public readonly CollectedClientData $clientDataJSON,
        public readonly null|AuthenticationExtensions $clientExtensionResults = null,
    ) {
    }
}
