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

namespace Webauthn\Bundle\Tests\Functional;

use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Webauthn\Bundle\Event\PublicKeyCredentialSourceRegistrationCompleted;
use Webauthn\Bundle\Security\Authentication\Token\WebauthnToken;

final class LoginAfterRegistration
{
    /**
     * @var TokenStorageInterface
     */
    private $tokenStorage;

    /**
     * @var UserRepository
     */
    private $userRepository;

    public function __construct(TokenStorageInterface $tokenStorage, UserRepository $userRepository)
    {
        $this->tokenStorage = $tokenStorage;
        $this->userRepository = $userRepository;
    }

    public function __invoke(PublicKeyCredentialSourceRegistrationCompleted $event): void
    {
        $userEntity = $event->getPublicKeyCredentialCreationOptions()->getUser();
        $user = new User(
            $userEntity->getId(),
            $userEntity->getName(),
            []
        );
        $this->userRepository->saveUser($user);

        $token = new WebauthnToken(
            $event->getPublicKeyCredentialCreationOptions()->getUser(),
            $event->getPublicKeyCredentialCreationOptions(),
            $event->getPublicKeyCredentialSource()->getPublicKeyCredentialDescriptor(),
            $event->getAuthenticatorAttestationResponse()->getAttestationObject()->getAuthData()->isUserPresent(),
            $event->getAuthenticatorAttestationResponse()->getAttestationObject()->getAuthData()->isUserVerified(),
            $event->getAuthenticatorAttestationResponse()->getAttestationObject()->getAuthData()->getReservedForFutureUse1(),
            $event->getAuthenticatorAttestationResponse()->getAttestationObject()->getAuthData()->getReservedForFutureUse2(),
            $event->getAuthenticatorAttestationResponse()->getAttestationObject()->getAuthData()->getSignCount(),
            $event->getAuthenticatorAttestationResponse()->getAttestationObject()->getAuthData()->getExtensions(),
            $event->getProviderKey(),
            $user->getRoles()
        );
        $token->setUser($user);
        $token->setAuthenticated(true);
        $this->tokenStorage->setToken($token);
    }
}
