<?php

declare(strict_types=1);

namespace Webauthn\AuthenticationExtensions\Uvm;

final class UvmEntry
{
    /**
     * @param positive-int $userVerificationMethod
     * @param positive-int $keyProtectionType
     * @param positive-int $matcherProtectionType
     */
    public function __construct(
        public readonly int $userVerificationMethod,
        public readonly int $keyProtectionType,
        public readonly int $matcherProtectionType,
    )
    {}

    /**
     * @param positive-int $userVerificationMethod
     * @param positive-int $keyProtectionType
     * @param positive-int $matcherProtectionType
     */
    public static function create(int $userVerificationMethod, int $keyProtectionType, int $matcherProtectionType): self
    {
        return new self($userVerificationMethod, $keyProtectionType, $matcherProtectionType);
    }
}
