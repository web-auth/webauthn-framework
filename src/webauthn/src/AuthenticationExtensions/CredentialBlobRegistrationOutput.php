<?php

declare(strict_types=1);

namespace Webauthn\AuthenticationExtensions;

use function is_bool;
use Webauthn\Exception\AuthenticationExtensionException;

/**
 * CTAP 2.1 §12.2: typed view of the `credBlob` REGISTRATION output.
 *
 * The authenticator returns a CBOR boolean inside
 * `authData.extensions.credBlob` indicating whether the blob payload sent
 * via {@see CredentialBlobInputExtension} was successfully stored. A `false`
 * (or absent) result means the blob was dropped — typically because the
 * authenticator does not implement the extension.
 *
 * For the assertion side (where the authenticator returns the previously
 * stored bytes), see {@see CredentialBlobAssertionOutput}.
 *
 * @see https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#sctn-credBlob-extension
 */
final readonly class CredentialBlobRegistrationOutput
{
    public function __construct(
        public bool $stored,
    ) {
    }

    public static function create(bool $stored): self
    {
        return new self($stored);
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
        is_bool($value) || throw AuthenticationExtensionException::create(
            'The "credBlob" registration output must be a boolean.'
        );

        return new self($value);
    }
}
