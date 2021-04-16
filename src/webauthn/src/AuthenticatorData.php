<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2020 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Webauthn;

use JetBrains\PhpStorm\Pure;
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

    #[Pure]
    public function __construct(protected string $authData, protected string $rpIdHash, protected string $flags, protected int $signCount, protected ?AttestedCredentialData $attestedCredentialData, protected ?AuthenticationExtensionsClientOutputs $extensions)
    {
    }

    #[Pure]
    public function getAuthData(): string
    {
        return $this->authData;
    }

    #[Pure]
    public function getRpIdHash(): string
    {
        return $this->rpIdHash;
    }

    #[Pure]
    public function isUserPresent(): bool
    {
        return 0 !== (ord($this->flags) & self::FLAG_UP);
    }

    #[Pure]
    public function isUserVerified(): bool
    {
        return 0 !== (ord($this->flags) & self::FLAG_UV);
    }

    #[Pure]
    public function hasAttestedCredentialData(): bool
    {
        return 0 !== (ord($this->flags) & self::FLAG_AT);
    }

    #[Pure]
    public function hasExtensions(): bool
    {
        return 0 !== (ord($this->flags) & self::FLAG_ED);
    }

    #[Pure]
    public function getReservedForFutureUse1(): int
    {
        return ord($this->flags) & self::FLAG_RFU1;
    }

    #[Pure]
    public function getReservedForFutureUse2(): int
    {
        return ord($this->flags) & self::FLAG_RFU2;
    }

    #[Pure]
    public function getSignCount(): int
    {
        return $this->signCount;
    }

    #[Pure]
    public function getAttestedCredentialData(): ?AttestedCredentialData
    {
        return $this->attestedCredentialData;
    }

    #[Pure]
    public function getExtensions(): ?AuthenticationExtensionsClientOutputs
    {
        return null !== $this->extensions && $this->hasExtensions() ? $this->extensions : null;
    }
}
