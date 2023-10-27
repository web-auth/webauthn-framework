<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Security\Authentication\Token;

use Symfony\Component\Security\Core\Authentication\Token\AbstractToken;
use Webauthn\AuthenticationExtensions\AuthenticationExtensions;
use Webauthn\Bundle\Security\Authorization\Voter\IsUserPresentVoter;
use Webauthn\Bundle\Security\Authorization\Voter\IsUserVerifiedVoter;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialOptions;
use Webauthn\PublicKeyCredentialUserEntity;

class WebauthnToken extends AbstractToken implements WebauthnTokenInterface
{
    public function __construct(
        private readonly PublicKeyCredentialUserEntity $publicKeyCredentialUserEntity,
        private readonly PublicKeyCredentialOptions $publicKeyCredentialOptions,
        private readonly PublicKeyCredentialDescriptor $publicKeyCredentialDescriptor,
        private readonly bool $isUserPresent,
        private readonly bool $isUserVerified,
        private readonly int $reservedForFutureUse1,
        private readonly int $reservedForFutureUse2,
        private readonly int $signCount,
        private readonly null|AuthenticationExtensions $extensions,
        private readonly string $firewallName,
        array $roles = [],
        private readonly bool $isBackupEligible = false,
        private readonly bool $isBackedUp = false,
    ) {
        parent::__construct($roles);
    }

    /**
     * @return array<mixed>
     */
    public function __serialize(): array
    {
        return [
            $this->publicKeyCredentialUserEntity,
            $this->publicKeyCredentialDescriptor,
            $this->publicKeyCredentialOptions,
            $this->isUserPresent,
            $this->isUserVerified,
            $this->isBackupEligible,
            $this->isBackedUp,
            $this->reservedForFutureUse1,
            $this->reservedForFutureUse2,
            $this->signCount,
            $this->extensions,
            $this->firewallName,
            parent::__serialize(),
        ];
    }

    /**
     * @param array<mixed> $data
     */
    public function __unserialize(array $data): void
    {
        [
            $this->publicKeyCredentialUserEntity,
            $this->publicKeyCredentialDescriptor,
            $this->publicKeyCredentialOptions,
            $this->isUserPresent,
            $this->isUserVerified,
            $this->isBackupEligible,
            $this->isBackedUp,
            $this->reservedForFutureUse1,
            $this->reservedForFutureUse2,
            $this->signCount,
            $this->extensions,
            $this->firewallName,
            $parentData
        ] = $data;

        parent::__unserialize($parentData);
    }

    public function getCredentials(): PublicKeyCredentialDescriptor
    {
        return $this->getPublicKeyCredentialDescriptor();
    }

    public function getPublicKeyCredentialUserEntity(): PublicKeyCredentialUserEntity
    {
        return $this->publicKeyCredentialUserEntity;
    }

    public function getPublicKeyCredentialDescriptor(): PublicKeyCredentialDescriptor
    {
        return $this->publicKeyCredentialDescriptor;
    }

    public function getPublicKeyCredentialOptions(): PublicKeyCredentialOptions
    {
        return $this->publicKeyCredentialOptions;
    }

    public function isUserPresent(): bool
    {
        return $this->isUserPresent;
    }

    public function isUserVerified(): bool
    {
        return $this->isUserVerified;
    }

    public function getReservedForFutureUse1(): int
    {
        return $this->reservedForFutureUse1;
    }

    public function getReservedForFutureUse2(): int
    {
        return $this->reservedForFutureUse2;
    }

    public function getSignCount(): int
    {
        return $this->signCount;
    }

    public function isBackupEligible(): bool
    {
        return $this->isBackupEligible;
    }

    public function isBackedUp(): bool
    {
        return $this->isBackedUp;
    }

    public function getExtensions(): ?AuthenticationExtensions
    {
        return $this->extensions;
    }

    public function getFirewallName(): string
    {
        return $this->firewallName;
    }

    /**
     * @return string[]
     */
    public function getAttributes(): array
    {
        $attributes = parent::getAttributes();
        if ($this->isUserVerified) {
            $attributes[] = IsUserVerifiedVoter::IS_USER_VERIFIED;
        }
        if ($this->isUserPresent) {
            $attributes[] = IsUserPresentVoter::IS_USER_PRESENT;
        }

        return $attributes;
    }
}
