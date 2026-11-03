<?php

declare(strict_types=1);

namespace Webauthn\AuthenticationExtensions;

/**
 * CTAP 2.1 §12.1: `credProtect` authenticator extension input.
 *
 * The relying party uses this extension to request a specific credential
 * protection policy at registration time. The W3C WebAuthn binding exposes
 * it on the client side as `credentialProtectionPolicy` (a string), with an
 * optional companion `enforceCredentialProtectionPolicy` boolean — the user
 * agent translates both to the CTAP `credProtect` authenticator extension
 * (uint 1, 2 or 3) when talking to the authenticator.
 *
 * Use {@see self::userVerificationOptional()},
 * {@see self::userVerificationOptionalWithCredentialIDList()} or
 * {@see self::userVerificationRequired()} to attach the policy. Add
 * {@see self::enforce()} alongside it when you want the user agent to fail
 * registration rather than silently downgrade the policy on authenticators
 * that do not honour `credProtect`.
 *
 * @see https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#sctn-credProtect-extension
 */
final class CredentialProtectionInputExtension extends AuthenticationExtension
{
    public const POLICY_USER_VERIFICATION_OPTIONAL = 'userVerificationOptional';

    public const POLICY_USER_VERIFICATION_OPTIONAL_WITH_CREDENTIAL_ID_LIST = 'userVerificationOptionalWithCredentialIDList';

    public const POLICY_USER_VERIFICATION_REQUIRED = 'userVerificationRequired';

    public const POLICIES = [
        self::POLICY_USER_VERIFICATION_OPTIONAL,
        self::POLICY_USER_VERIFICATION_OPTIONAL_WITH_CREDENTIAL_ID_LIST,
        self::POLICY_USER_VERIFICATION_REQUIRED,
    ];

    public static function userVerificationOptional(): AuthenticationExtension
    {
        return self::create('credentialProtectionPolicy', self::POLICY_USER_VERIFICATION_OPTIONAL);
    }

    public static function userVerificationOptionalWithCredentialIDList(): AuthenticationExtension
    {
        return self::create(
            'credentialProtectionPolicy',
            self::POLICY_USER_VERIFICATION_OPTIONAL_WITH_CREDENTIAL_ID_LIST,
        );
    }

    public static function userVerificationRequired(): AuthenticationExtension
    {
        return self::create('credentialProtectionPolicy', self::POLICY_USER_VERIFICATION_REQUIRED);
    }

    /**
     * Companion `enforceCredentialProtectionPolicy: true` extension. Add this
     * alongside the policy extension when registration must fail rather than
     * silently downgrade on authenticators that do not honour `credProtect`.
     */
    public static function enforce(): AuthenticationExtension
    {
        return self::create('enforceCredentialProtectionPolicy', true);
    }
}
