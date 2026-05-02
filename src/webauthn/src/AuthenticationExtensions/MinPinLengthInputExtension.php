<?php

declare(strict_types=1);

namespace Webauthn\AuthenticationExtensions;

/**
 * CTAP 2.1 §12.4: `minPinLength` authenticator extension input.
 *
 * Defined by FIDO Alliance, not by the W3C WebAuthn specification, but
 * transported through WebAuthn's generic authenticator-extensions mechanism.
 * The input is a boolean attached to a registration ceremony; when the
 * relying party is on the authenticator's enterprise allow-list, the
 * authenticator returns the configured minimum PIN length as a CBOR uint
 * inside `authData.extensions.minPinLength`. Use {@see MinPinLengthOutput}
 * for typed access to that value.
 *
 * @see https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#sctn-minpinlength-extension
 */
final class MinPinLengthInputExtension extends AuthenticationExtension
{
    public static function enable(): AuthenticationExtension
    {
        return self::create('minPinLength', true);
    }

    public static function disable(): AuthenticationExtension
    {
        return self::create('minPinLength', false);
    }
}
