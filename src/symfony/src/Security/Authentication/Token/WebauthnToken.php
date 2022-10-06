<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Security\Authentication\Token;

use const JSON_THROW_ON_ERROR;
use Symfony\Component\Security\Core\Authentication\Token\AbstractToken;
use Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientOutputs;
use Webauthn\Bundle\Security\Authorization\Voter\IsUserPresentVoter;
use Webauthn\Bundle\Security\Authorization\Voter\IsUserVerifiedVoter;
use Webauthn\Exception\InvalidDataException;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialOptions;
use Webauthn\PublicKeyCredentialUserEntity;

class WebauthnToken extends AbstractToken implements WebauthnTokenInterface
{
    /**
     * {@inheritdoc}
     */
    public function __construct(
        private PublicKeyCredentialUserEntity $publicKeyCredentialUserEntity,
        private PublicKeyCredentialOptions $publicKeyCredentialOptions,
        private PublicKeyCredentialDescriptor $publicKeyCredentialDescriptor,
        private readonly bool $isUserPresent,
        private readonly bool $isUserVerified,
        private readonly int $reservedForFutureUse1,
        private readonly int $reservedForFutureUse2,
        private readonly int $signCount,
        private ?AuthenticationExtensionsClientOutputs $extensions,
        private readonly string $firewallName,
        array $roles = []
    ) {
        parent::__construct($roles);
    }

    /**
     * @return array<mixed>
     */
    public function __serialize(): array
    {
        return [
            json_encode($this->publicKeyCredentialUserEntity, JSON_THROW_ON_ERROR),
            json_encode($this->publicKeyCredentialDescriptor, JSON_THROW_ON_ERROR),
            $this->publicKeyCredentialOptions::class,
            json_encode($this->publicKeyCredentialOptions, JSON_THROW_ON_ERROR),
            $this->isUserPresent,
            $this->isUserVerified,
            $this->reservedForFutureUse1,
            $this->reservedForFutureUse2,
            $this->signCount,
            $this->extensions,
            $this->firewallName,
            parent::__serialize(),
        ];
    }

    /**
     * @param array<mixed> $serialized
     */
    public function __unserialize(array $serialized): void
    {
        [
            $publicKeyCredentialUserEntity,
            $publicKeyCredentialDescriptor,
            $publicKeyCredentialOptionsClass,
            $publicKeyCredentialOptions,
            $this->isUserPresent,
            $this->isUserVerified,
            $this->reservedForFutureUse1,
            $this->reservedForFutureUse2,
            $this->signCount,
            $extensions,
            $this->firewallName,
            $parentData
        ] = $serialized;
        is_subclass_of(
            $publicKeyCredentialOptionsClass,
            PublicKeyCredentialOptions::class
        ) || throw InvalidDataException::create($serialized, 'Invalid PublicKeyCredentialOptions class');
        $this->publicKeyCredentialUserEntity = PublicKeyCredentialUserEntity::createFromString(
            $publicKeyCredentialUserEntity
        );
        $this->publicKeyCredentialDescriptor = PublicKeyCredentialDescriptor::createFromString(
            $publicKeyCredentialDescriptor
        );
        $this->publicKeyCredentialOptions = $publicKeyCredentialOptionsClass::createFromString(
            $publicKeyCredentialOptions
        );

        $this->extensions = null;
        if ($extensions !== null) {
            $this->extensions = AuthenticationExtensionsClientOutputs::createFromString($extensions);
        }
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

    public function getExtensions(): ?AuthenticationExtensionsClientOutputs
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
