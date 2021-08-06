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

namespace Webauthn\Bundle\Security\Authentication\Provider;

use Assert\Assertion;
use JetBrains\PhpStorm\Pure;
use Symfony\Component\Security\Core\Authentication\Provider\AuthenticationProviderInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\User\UserCheckerInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Throwable;
use Webauthn\Bundle\Security\Authentication\Token\WebauthnToken;

class WebauthnProvider implements AuthenticationProviderInterface
{
    #[Pure]
    public function __construct(private UserCheckerInterface $userChecker, private UserProviderInterface $userProvider)
    {
    }

    /**
     * {@inheritdoc}
     */
    public function authenticate(TokenInterface $token): WebauthnToken
    {
        Assertion::isInstanceOf($token, WebauthnToken::class, 'The token is not supported by this authentication provider.');
        $user = $this->userProvider->loadUserByIdentifier($token->getUserIdentifier());
        try {
            $this->userChecker->checkPreAuth($user);
            $this->userChecker->checkPostAuth($user);
        } catch (Throwable $throwable) {
            throw new AuthenticationException('The Webauthn authentication failed.', $throwable->getCode(), $throwable);
        }

        $authenticatedToken = new WebauthnToken(
            $token->getPublicKeyCredentialUserEntity(),
            $token->getPublicKeyCredentialOptions(),
            $token->getCredentials(),
            $token->isUserPresent(),
            $token->isUserVerified(),
            $token->getReservedForFutureUse1(),
            $token->getReservedForFutureUse2(),
            $token->getSignCount(),
            $token->getExtensions(),
            $token->getProviderKey(),
            $user->getRoles()
        );

        $authenticatedToken->setUser($user);
        $authenticatedToken->setAuthenticated(true);

        return $authenticatedToken;
    }

    /**
     * {@inheritdoc}
     */
    #[Pure]
    public function supports(TokenInterface $token): bool
    {
        return $token instanceof WebauthnToken;
    }
}
