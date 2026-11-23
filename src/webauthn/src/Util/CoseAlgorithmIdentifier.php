<?php

declare(strict_types=1);

namespace Webauthn\Util;

use function is_int;
use function is_string;

/**
 * Tells whether a value read from an attestation statement is a COSE algorithm identifier, an integer.
 *
 * The CBOR decoder normalizes an integer into its decimal string, so the integer itself and that exact string are
 * accepted. Any other string is refused: casting "-065535", "-65535 " or "-65535abc" to an integer gives -65535, and an
 * algorithm refused by its identifier would be accepted under one of those spellings.
 *
 * @internal
 *
 * @see https://www.w3.org/TR/webauthn-3/#sctn-alg-identifier
 */
final readonly class CoseAlgorithmIdentifier
{
    public static function isValid(mixed $value): bool
    {
        if (is_int($value)) {
            return true;
        }

        return is_string($value) && (string) (int) $value === $value;
    }
}
