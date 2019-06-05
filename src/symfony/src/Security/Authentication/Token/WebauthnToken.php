<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2019 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Webauthn\Bundle\Security\Authentication\Token;

use Assert\Assertion;
use function Safe\json_encode;
use Symfony\Component\Security\Core\Authentication\Token\AbstractToken;
use Symfony\Component\Security\Core\Role\Role;
use Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientOutputs;
use Webauthn\Bundle\Security\Voter\IsUserPresentVoter;
use Webauthn\Bundle\Security\Voter\IsUserVerifiedVoter;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialUserEntity;

class WebauthnToken extends AbstractToken
{
    /**
     * @var string
     */
    private $providerKey;

    /**
     * @var PublicKeyCredentialUserEntity
     */
    private $publicKeyCredentialUserEntity;

    /**
     * @var PublicKeyCredentialDescriptor
     */
    private $publicKeyCredentialDescriptor;

    /**
     * @var bool
     */
    private $isUserPresent;

    /**
     * @var bool
     */
    private $isUserVerified;

    /**
     * @var int
     */
    private $signCount;

    /**
     * @var AuthenticationExtensionsClientOutputs|null
     */
    private $extensions;

    /**
     * @var int
     */
    private $reservedForFutureUse1;

    /**
     * @var int
     */
    private $reservedForFutureUse2;

    /**
     * @var PublicKeyCredentialRequestOptions
     */
    private $publicKeyCredentialRequestOptions;

    /**
     * {@inheritDoc}
     */
    public function __construct(PublicKeyCredentialUserEntity $publicKeyCredentialUserEntity, PublicKeyCredentialRequestOptions $publicKeyCredentialRequestOptions, PublicKeyCredentialDescriptor $publicKeyCredentialDescriptor, bool $isUserPresent, bool $isUserVerified, int $reservedForFutureUse1, int $reservedForFutureUse2, int $signCount, ?AuthenticationExtensionsClientOutputs $extensions, string $providerKey, array $roles = [])
    {
        parent::__construct($roles);
        Assertion::notEmpty($providerKey, '$providerKey must not be empty.');

        $this->setUser($publicKeyCredentialUserEntity->getName());
        $this->publicKeyCredentialUserEntity = $publicKeyCredentialUserEntity;
        $this->providerKey = $providerKey;
        $this->publicKeyCredentialDescriptor = $publicKeyCredentialDescriptor;
        $this->isUserPresent = $isUserPresent;
        $this->isUserVerified = $isUserVerified;
        $this->signCount = $signCount;
        $this->extensions = $extensions;
        $this->reservedForFutureUse1 = $reservedForFutureUse1;
        $this->reservedForFutureUse2 = $reservedForFutureUse2;
        $this->publicKeyCredentialRequestOptions = $publicKeyCredentialRequestOptions;
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

    public function getPublicKeyCredentialRequestOptions(): PublicKeyCredentialRequestOptions
    {
        return $this->publicKeyCredentialRequestOptions;
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

    public function getProviderKey(): string
    {
        return $this->providerKey;
    }

    /**
     * {@inheritDoc}
     */
    public function __serialize(): array
    {
        return [
            json_encode($this->publicKeyCredentialUserEntity),
            json_encode($this->publicKeyCredentialDescriptor),
            json_encode($this->publicKeyCredentialRequestOptions),
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

    public function getAttributes()
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

    /**
     * {@inheritDoc}
     */
    public function __unserialize(array $serialized): void
    {
        [
            $publicKeyCredentialUserEntity,
            $publicKeyCredentialDescriptor,
            $publicKeyCredentialRequestOptions,
            $this->isUserPresent,
            $this->isUserVerified,
            $this->reservedForFutureUse1,
            $this->reservedForFutureUse2,
            $this->signCount,
            $extensions,
            $this->providerKey,
            $parentData
            ] = $serialized;
        $this->publicKeyCredentialUserEntity = PublicKeyCredentialUserEntity::createFromString($publicKeyCredentialUserEntity);
        $this->publicKeyCredentialDescriptor = PublicKeyCredentialDescriptor::createFromString($publicKeyCredentialDescriptor);
        $this->publicKeyCredentialRequestOptions = PublicKeyCredentialRequestOptions::createFromString($publicKeyCredentialRequestOptions);

        $this->extensions = null;
        if (null !== $extensions) {
            $this->extensions = AuthenticationExtensionsClientOutputs::createFromString($extensions);
        }
        parent::__unserialize($parentData);
    }
}
