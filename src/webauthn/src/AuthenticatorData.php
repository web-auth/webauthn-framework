<?php

declare(strict_types=1);

namespace Webauthn;

use Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientOutputs;
use function ord;

/**
 * @final
 * @see https://www.w3.org/TR/webauthn/#sec-authenticator-data
 * @see https://www.w3.org/TR/webauthn/#flags
 */
class AuthenticatorData
{
    final public const FLAG_UP = 0b00000001;

    final public const FLAG_RFU1 = 0b00000010;

    final public const FLAG_UV = 0b00000100;

    final public const FLAG_BE = 0b00001000;

    final public const FLAG_BS = 0b00010000;

    /**
     * TODO: remove bits 3 and 4 as they have been assigned to BE and BS in Webauthn level 3.
     */
    final public const FLAG_RFU2 = 0b00111000;

    final public const FLAG_AT = 0b01000000;

    final public const FLAG_ED = 0b10000000;

    public function __construct(
        public readonly string $authData,
        public readonly string $rpIdHash,
        public readonly string $flags,
        public readonly int $signCount,
        public readonly ?AttestedCredentialData $attestedCredentialData,
        public readonly ?AuthenticationExtensionsClientOutputs $extensions
    ) {
    }

    /**
     * @deprecated since 4.7.0. Please use the property directly.
     */
    public function getAuthData(): string
    {
        return $this->authData;
    }

    /**
     * @deprecated since 4.7.0. Please use the property directly.
     */
    public function getRpIdHash(): string
    {
        return $this->rpIdHash;
    }

    public function isUserPresent(): bool
    {
        return 0 !== (ord($this->flags) & self::FLAG_UP);
    }

    public function isUserVerified(): bool
    {
        return 0 !== (ord($this->flags) & self::FLAG_UV);
    }

    public function isBackupEligible(): bool
    {
        return 0 !== (ord($this->flags) & self::FLAG_BE);
    }

    public function isBackedUp(): bool
    {
        return 0 !== (ord($this->flags) & self::FLAG_BS);
    }

    public function hasAttestedCredentialData(): bool
    {
        return 0 !== (ord($this->flags) & self::FLAG_AT);
    }

    public function hasExtensions(): bool
    {
        return 0 !== (ord($this->flags) & self::FLAG_ED);
    }

    public function getReservedForFutureUse1(): int
    {
        return ord($this->flags) & self::FLAG_RFU1;
    }

    public function getReservedForFutureUse2(): int
    {
        return ord($this->flags) & self::FLAG_RFU2;
    }

    /**
     * @deprecated since 4.7.0. Please use the property directly.
     */
    public function getSignCount(): int
    {
        return $this->signCount;
    }

    /**
     * @deprecated since 4.7.0. Please use the property directly.
     */
    public function getAttestedCredentialData(): ?AttestedCredentialData
    {
        return $this->attestedCredentialData;
    }

    /**
     * @deprecated since 4.7.0. Please use the property directly.
     */
    public function getExtensions(): ?AuthenticationExtensionsClientOutputs
    {
        return $this->extensions !== null && $this->hasExtensions() ? $this->extensions : null;
    }
}
