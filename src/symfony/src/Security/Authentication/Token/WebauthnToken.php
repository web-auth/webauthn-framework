<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Security\Authentication\Token;

use Assert\Assertion;
use JetBrains\PhpStorm\Pure;
use function Safe\json_encode;
use Symfony\Component\Security\Core\Authentication\Token\AbstractToken;
use Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientOutputs;
use Webauthn\Bundle\Security\Voter\IsUserPresentVoter;
use Webauthn\Bundle\Security\Voter\IsUserVerifiedVoter;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialOptions;
use Webauthn\PublicKeyCredentialUserEntity;

class WebauthnToken extends AbstractToken
{
    private string $providerKey;

    private PublicKeyCredentialUserEntity $publicKeyCredentialUserEntity;

    /**
     * {@inheritdoc}
     */
    public function __construct(PublicKeyCredentialUserEntity $publicKeyCredentialUserEntity, private PublicKeyCredentialOptions $publicKeyCredentialOptions, private PublicKeyCredentialDescriptor $publicKeyCredentialDescriptor, private bool $isUserPresent, private bool $isUserVerified, private int $reservedForFutureUse1, private int $reservedForFutureUse2, private int $signCount, private ?AuthenticationExtensionsClientOutputs $extensions, string $providerKey, array $roles = [])
    {
        parent::__construct($roles);
        Assertion::notEmpty($providerKey, '$providerKey must not be empty.');

        $this->setUser($publicKeyCredentialUserEntity->getName());
        $this->publicKeyCredentialUserEntity = $publicKeyCredentialUserEntity;
        $this->providerKey = $providerKey;
    }

    /**
     * {@inheritdoc}
     */
    public function __serialize(): array
    {
        return [
            json_encode($this->publicKeyCredentialUserEntity),
            json_encode($this->publicKeyCredentialDescriptor),
            $this->publicKeyCredentialOptions::class,
            json_encode($this->publicKeyCredentialOptions),
            $this->isUserPresent,
            $this->isUserVerified,
            $this->reservedForFutureUse1,
            $this->reservedForFutureUse2,
            $this->signCount,
            $this->extensions,
            $this->providerKey,
            parent::__serialize(),
        ];
    }

    /**
     * {@inheritdoc}
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
            $this->providerKey,
            $parentData
            ] = $serialized;
        Assertion::subclassOf($publicKeyCredentialOptionsClass, PublicKeyCredentialOptions::class, 'Invalid PublicKeyCredentialOptions class');
        $this->publicKeyCredentialUserEntity = PublicKeyCredentialUserEntity::createFromString($publicKeyCredentialUserEntity);
        $this->publicKeyCredentialDescriptor = PublicKeyCredentialDescriptor::createFromString($publicKeyCredentialDescriptor);
        $this->publicKeyCredentialOptions = $publicKeyCredentialOptionsClass::createFromString($publicKeyCredentialOptions);

        $this->extensions = null;
        if (null !== $extensions) {
            $this->extensions = AuthenticationExtensionsClientOutputs::createFromString($extensions);
        }
        parent::__unserialize($parentData);
    }

    #[Pure]
    public function getUserIdentifier(): string
    {
        return $this->publicKeyCredentialUserEntity->getId();
    }

    #[Pure]
    public function getCredentials(): PublicKeyCredentialDescriptor
    {
        return $this->getPublicKeyCredentialDescriptor();
    }

    #[Pure]
    public function getPublicKeyCredentialUserEntity(): PublicKeyCredentialUserEntity
    {
        return $this->publicKeyCredentialUserEntity;
    }

    #[Pure]
    public function getPublicKeyCredentialDescriptor(): PublicKeyCredentialDescriptor
    {
        return $this->publicKeyCredentialDescriptor;
    }

    #[Pure]
    public function getPublicKeyCredentialOptions(): PublicKeyCredentialOptions
    {
        return $this->publicKeyCredentialOptions;
    }

    #[Pure]
    public function isUserPresent(): bool
    {
        return $this->isUserPresent;
    }

    #[Pure]
    public function isUserVerified(): bool
    {
        return $this->isUserVerified;
    }

    #[Pure]
    public function getReservedForFutureUse1(): int
    {
        return $this->reservedForFutureUse1;
    }

    #[Pure]
    public function getReservedForFutureUse2(): int
    {
        return $this->reservedForFutureUse2;
    }

    #[Pure]
    public function getSignCount(): int
    {
        return $this->signCount;
    }

    #[Pure]
    public function getExtensions(): ?AuthenticationExtensionsClientOutputs
    {
        return $this->extensions;
    }

    #[Pure]
    public function getProviderKey(): string
    {
        return $this->providerKey;
    }

    #[Pure]
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
