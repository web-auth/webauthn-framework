<?php

declare(strict_types=1);

namespace Webauthn;

use function in_array;
use InvalidArgumentException;
use function is_string;
use Webauthn\AuthenticationExtensions\AuthenticationExtension;
use Webauthn\AuthenticationExtensions\AuthenticationExtensions;
use Webauthn\Exception\InvalidDataException;

final class PublicKeyCredentialRequestOptions extends PublicKeyCredentialOptions
{
    public const USER_VERIFICATION_REQUIREMENT_DEFAULT = null;

    public const USER_VERIFICATION_REQUIREMENT_REQUIRED = 'required';

    public const USER_VERIFICATION_REQUIREMENT_PREFERRED = 'preferred';

    public const USER_VERIFICATION_REQUIREMENT_DISCOURAGED = 'discouraged';

    public const USER_VERIFICATION_REQUIREMENTS = [
        self::USER_VERIFICATION_REQUIREMENT_DEFAULT,
        self::USER_VERIFICATION_REQUIREMENT_REQUIRED,
        self::USER_VERIFICATION_REQUIREMENT_PREFERRED,
        self::USER_VERIFICATION_REQUIREMENT_DISCOURAGED,
    ];

    /**
     * `CredentialUiMode` values for `navigator.credentials.get()`. Defined by
     * the WHATWG/W3C Credential Management spec (editor's draft, §2.3.3).
     *
     * - {@see UI_MODE_AUTO} (default) — usual UA flow.
     * - {@see UI_MODE_IMMEDIATE} — synchronous attempt: the user agent must
     *   either return a credential immediately available locally or fail
     *   with `NotAllowedError`. Useful for silent re-auth.
     *
     * `uiMode` is a separate dictionary member from `mediation`. It does NOT
     * belong to `CredentialMediationRequirement` (which stays
     * `silent | optional | conditional | required`).
     *
     * @see https://w3c.github.io/webappsec-credential-management/#enumdef-credentialuimode
     */
    public const UI_MODE_AUTO = 'auto';

    public const UI_MODE_IMMEDIATE = 'immediate';

    public const UI_MODES = [self::UI_MODE_AUTO, self::UI_MODE_IMMEDIATE];

    /**
     * @param PublicKeyCredentialDescriptor[] $allowCredentials
     * @param null|AuthenticationExtensions|array<array-key, AuthenticationExtension> $extensions
     * @param string[] $hints
     * @param string[] $attestationFormats RP-preferred attestation statement formats, in priority order (WebAuthn L3 §5.5).
     */
    public function __construct(
        string $challenge,
        public null|string $rpId = null,
        public array $allowCredentials = [],
        public null|string $userVerification = null,
        null|int $timeout = null,
        null|array|AuthenticationExtensions $extensions = null,
        array $hints = [],
        public null|string $uiMode = null,
        public null|string $attestation = null,
        public array $attestationFormats = [],
    ) {
        in_array($userVerification, self::USER_VERIFICATION_REQUIREMENTS, true) || throw InvalidDataException::create(
            $userVerification,
            'Invalid user verification requirement'
        );
        $uiMode === null || in_array($uiMode, self::UI_MODES, true) || throw InvalidDataException::create(
            $uiMode,
            'Invalid UI mode'
        );
        in_array(
            $attestation,
            PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCES,
            true,
        ) || throw InvalidDataException::create($attestation, 'Invalid attestation conveyance mode');
        foreach ($attestationFormats as $attestationFormat) {
            is_string($attestationFormat) || throw new InvalidArgumentException(
                'Invalid type for $attestationFormats: each entry must be a string'
            );
        }
        parent::__construct(
            $challenge,
            $timeout,
            $extensions,
            $hints
        );
    }

    /**
     * @param PublicKeyCredentialDescriptor[] $allowCredentials
     * @param positive-int $timeout
     * @param null|AuthenticationExtensions|array<array-key, AuthenticationExtension> $extensions
     * @param string[] $hints
     * @param string[] $attestationFormats
     */
    public static function create(
        string $challenge,
        null|string $rpId = null,
        array $allowCredentials = [],
        null|string $userVerification = null,
        null|int $timeout = null,
        null|array|AuthenticationExtensions $extensions = null,
        array $hints = [],
        null|string $uiMode = null,
        null|string $attestation = null,
        array $attestationFormats = [],
    ): self {
        return new self(
            $challenge,
            $rpId,
            $allowCredentials,
            $userVerification,
            $timeout,
            $extensions,
            $hints,
            $uiMode,
            $attestation,
            $attestationFormats,
        );
    }
}
