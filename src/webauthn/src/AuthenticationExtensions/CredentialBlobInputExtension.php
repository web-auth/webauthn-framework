<?php

declare(strict_types=1);

namespace Webauthn\AuthenticationExtensions;

use ParagonIE\ConstantTime\Base64UrlSafe;
use function strlen;
use Webauthn\Exception\AuthenticationExtensionException;

/**
 * CTAP 2.1 §12.2: `credBlob` registration input.
 *
 * Asks the authenticator to store up to 32 bytes alongside the credential
 * being created. The blob can later be retrieved during an assertion via
 * {@see GetCredentialBlobInputExtension}.
 *
 * The wire format on the WebAuthn JSON side is base64url; the Stimulus
 * base controller decodes it back to an `ArrayBuffer` before calling
 * `navigator.credentials.create()`.
 *
 * @see https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#sctn-credBlob-extension
 */
final class CredentialBlobInputExtension extends AuthenticationExtension
{
    public const MAX_LENGTH = 32;

    /**
     * @param string $blob Raw bytes (≤32). Encoded to base64url before transport.
     *
     * @throws AuthenticationExtensionException if the blob exceeds {@see self::MAX_LENGTH} bytes.
     */
    public static function withBlob(string $blob): AuthenticationExtension
    {
        strlen($blob) <= self::MAX_LENGTH || throw AuthenticationExtensionException::create(
            'The "credBlob" payload must not exceed 32 bytes.'
        );

        return self::create('credBlob', Base64UrlSafe::encodeUnpadded($blob));
    }
}
