<?php

declare(strict_types=1);

namespace Webauthn\AuthenticationExtensions;

use function in_array;
use function is_int;
use Webauthn\Exception\AuthenticationExtensionException;

/**
 * CTAP 2.1 §12.1: typed view of the `credProtect` authenticator extension
 * output.
 *
 * The authenticator returns the protection policy it actually applied to the
 * newly created credential as a CBOR unsigned integer (1, 2 or 3) inside
 * `authData.extensions.credProtect`. The relying party can compare this to
 * the value it requested via {@see CredentialProtectionInputExtension} to
 * detect silent downgrades on authenticators that do not enforce the policy.
 *
 * Use {@see fromExtensions()} or {@see fromExtension()} to materialise the
 * value object from the extensions bag parsed off `authData`.
 *
 * @see https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#sctn-credProtect-extension
 */
final readonly class CredentialProtectionOutput
{
    public const POLICY_USER_VERIFICATION_OPTIONAL = 1;

    public const POLICY_USER_VERIFICATION_OPTIONAL_WITH_CREDENTIAL_ID_LIST = 2;

    public const POLICY_USER_VERIFICATION_REQUIRED = 3;

    public const POLICIES = [
        self::POLICY_USER_VERIFICATION_OPTIONAL,
        self::POLICY_USER_VERIFICATION_OPTIONAL_WITH_CREDENTIAL_ID_LIST,
        self::POLICY_USER_VERIFICATION_REQUIRED,
    ];

    public function __construct(
        public int $policy,
    ) {
        in_array($policy, self::POLICIES, true) || throw AuthenticationExtensionException::create(
            'The "credProtect" output must be 1, 2 or 3.'
        );
    }

    public static function create(int $policy): self
    {
        return new self($policy);
    }

    public static function fromExtensions(AuthenticationExtensions $extensions): ?self
    {
        if (! $extensions->has('credProtect')) {
            return null;
        }

        return self::fromExtension($extensions->get('credProtect'));
    }

    public static function fromExtension(AuthenticationExtension $extension): self
    {
        $extension->name === 'credProtect' || throw AuthenticationExtensionException::create(
            'The extension is not a "credProtect" extension.'
        );

        $value = $extension->value;
        is_int($value) || throw AuthenticationExtensionException::create(
            'The "credProtect" output must be an integer.'
        );

        return new self($value);
    }
}
