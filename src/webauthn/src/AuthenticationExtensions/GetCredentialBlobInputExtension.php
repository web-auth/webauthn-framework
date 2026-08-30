<?php

declare(strict_types=1);

namespace Webauthn\AuthenticationExtensions;

/**
 * CTAP 2.1 §12.2: `getCredBlob` assertion input.
 *
 * Asks the authenticator to return the blob previously stored against the
 * asserted credential via {@see CredentialBlobInputExtension}. The retrieved
 * bytes appear under `credBlob` inside `authData.extensions` — see
 * {@see CredentialBlobAssertionOutput} for typed access.
 *
 * @see https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#sctn-credBlob-extension
 */
final class GetCredentialBlobInputExtension extends AuthenticationExtension
{
    public static function enable(): AuthenticationExtension
    {
        return self::create('getCredBlob', true);
    }

    public static function disable(): AuthenticationExtension
    {
        return self::create('getCredBlob', false);
    }
}
