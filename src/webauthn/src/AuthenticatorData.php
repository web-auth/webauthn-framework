<?php

declare(strict_types=1);

namespace Webauthn;

use function ord;
use Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientOutputs;

/**
 * @see https://www.w3.org/TR/webauthn/#sec-authenticator-data
 */
class AuthenticatorData
{
    private const FLAG_UP = 0b00000001;

    private const FLAG_RFU1 = 0b00000010;

    private const FLAG_UV = 0b00000100;

    private const FLAG_RFU2 = 0b00111000;

    private const FLAG_AT = 0b01000000;

    private const FLAG_ED = 0b10000000;

    public function __construct(
        protected string $authData,
        protected string $rpIdHash,
        protected string $flags,
        protected int $signCount,
        protected ?AttestedCredentialData $attestedCredentialData,
        protected ?AuthenticationExtensionsClientOutputs $extensions
    ) {
    }

    public function getAuthData(): string
    {
        return $this->authData;
    }

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

    public function getSignCount(): int
    {
        return $this->signCount;
    }

    public function getAttestedCredentialData(): ?AttestedCredentialData
    {
        return $this->attestedCredentialData;
    }

    public function getExtensions(): ?AuthenticationExtensionsClientOutputs
    {
        return $this->extensions !== null && $this->hasExtensions() ? $this->extensions : null;
    }
}
