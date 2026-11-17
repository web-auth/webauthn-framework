<?php

declare(strict_types=1);

namespace Webauthn\AuthenticationExtensions;

use function is_int;
use Webauthn\Exception\AuthenticationExtensionException;

/**
 * CTAP 2.1 §12.4: typed view of the `minPinLength` authenticator extension
 * output.
 *
 * The authenticator returns the configured minimum PIN length as a CBOR
 * unsigned integer inside `authData.extensions.minPinLength`. The value is
 * only emitted when the relying party id is on the authenticator's enterprise
 * allow-list; if the RP requested the extension but the authenticator did
 * not return it, the extension is simply absent from the bag — that is not
 * an error.
 *
 * Use {@see fromExtensions()} or {@see fromExtension()} to materialise the
 * value object from the raw extensions bag parsed off `authData`.
 *
 * @see https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#sctn-minpinlength-extension
 */
final readonly class MinPinLengthOutput
{
    public function __construct(
        public int $minPinLength,
    ) {
        $minPinLength >= 0 || throw AuthenticationExtensionException::create(
            'The "minPinLength" output must be a non-negative integer.'
        );
    }

    public static function create(int $minPinLength): self
    {
        return new self($minPinLength);
    }

    public static function fromExtensions(AuthenticationExtensions $extensions): ?self
    {
        if (! $extensions->has('minPinLength')) {
            return null;
        }

        return self::fromExtension($extensions->get('minPinLength'));
    }

    public static function fromExtension(AuthenticationExtension $extension): self
    {
        $extension->name === 'minPinLength' || throw AuthenticationExtensionException::create(
            'The extension is not a "minPinLength" extension.'
        );

        $value = $extension->value;
        is_int($value) || throw AuthenticationExtensionException::create(
            'The "minPinLength" output must be an integer.'
        );

        return new self($value);
    }
}
