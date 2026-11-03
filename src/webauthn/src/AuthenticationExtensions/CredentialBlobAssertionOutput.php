<?php

declare(strict_types=1);

namespace Webauthn\AuthenticationExtensions;

use function is_string;
use function strlen;
use Webauthn\Exception\AuthenticationExtensionException;

/**
 * CTAP 2.1 §12.2: typed view of the `credBlob` ASSERTION output.
 *
 * When the relying party requested {@see GetCredentialBlobInputExtension} on
 * an assertion, the authenticator returns the bytes previously stored
 * against the credential (≤32) as a CBOR byte string inside
 * `authData.extensions.credBlob`. The bytes arrive here raw — no base64url
 * decoding required.
 *
 * For the registration-side success boolean, see
 * {@see CredentialBlobRegistrationOutput}.
 *
 * @see https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#sctn-credBlob-extension
 */
final readonly class CredentialBlobAssertionOutput
{
    public function __construct(
        public string $blob,
    ) {
        strlen($blob) <= CredentialBlobInputExtension::MAX_LENGTH || throw AuthenticationExtensionException::create(
            'The "credBlob" assertion output must not exceed 32 bytes.'
        );
    }

    public static function create(string $blob): self
    {
        return new self($blob);
    }

    public static function fromExtensions(AuthenticationExtensions $extensions): ?self
    {
        if (! $extensions->has('credBlob')) {
            return null;
        }

        return self::fromExtension($extensions->get('credBlob'));
    }

    public static function fromExtension(AuthenticationExtension $extension): self
    {
        $extension->name === 'credBlob' || throw AuthenticationExtensionException::create(
            'The extension is not a "credBlob" extension.'
        );

        $value = $extension->value;
        is_string($value) || throw AuthenticationExtensionException::create(
            'The "credBlob" assertion output must be a byte string.'
        );

        return new self($value);
    }
}
