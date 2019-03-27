<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Webauthn\SecurityBundle\Security\Authentication\Provider;

use Assert\Assertion;
use Symfony\Component\Security\Core\Authentication\Provider\AuthenticationProviderInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationServiceException;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use Symfony\Component\Security\Core\User\UserCheckerInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Webauthn\SecurityBundle\Model\CanHaveRegisteredSecurityDevices;
use Webauthn\SecurityBundle\Security\Authentication\Token\PreWebauthnToken;

class PreWebauthnProvider implements AuthenticationProviderInterface
{
    /**
     * @var UserCheckerInterface
     */
    private $userChecker;

    /**
     * @var string
     */
    private $providerKey;

    /**
     * @var UserProviderInterface
     */
    private $userProvider;

    public function __construct(UserCheckerInterface $userChecker, UserProviderInterface $userProvider, string $providerKey)
    {
        Assertion::notEmpty($providerKey, '$providerKey must not be empty.');

        $this->userChecker = $userChecker;
        $this->providerKey = $providerKey;
        $this->userProvider = $userProvider;
    }

    /**
     * {@inheritdoc}
     */
    public function authenticate(TokenInterface $token): TokenInterface
    {
        Assertion::isInstanceOf($token, PreWebauthnToken::class, 'The token is not supported by this authentication provider.');
        Assertion::eq($this->providerKey, $token->getProviderKey(), 'The token is not supported by this authentication provider.');

        return $this->processWithPreWebauthnToken($token);
    }

    /**
     * {@inheritdoc}
     */
    public function supports(TokenInterface $token): bool
    {
        return $token instanceof PreWebauthnToken && $this->providerKey === $token->getProviderKey();
    }

    private function processWithPreWebauthnToken(PreWebauthnToken $token): PreWebauthnToken
    {
        $username = $token->getUsername();
        if ('' === $username) {
            throw new AuthenticationServiceException('Invalid username.');
        }

        $user = $this->retrieveUser($username, $token);

        if (!$user instanceof CanHaveRegisteredSecurityDevices) {
            throw new AuthenticationServiceException('The user did not registered any security devices');
        }

        try {
            $this->userChecker->checkPreAuth($user);
        } catch (BadCredentialsException $e) {
            throw $e;
        } catch (\Exception $e) {
            throw new AuthenticationServiceException($e->getMessage(), 0, $e);
        }

        $authenticatedToken = new PreWebauthnToken(
            $username,
            $this->providerKey,
            $token->isRememberMe()
        );
        $authenticatedToken->setUser($user);
        $authenticatedToken->setAuthenticated(true);

        return $authenticatedToken;
    }

    private function retrieveUser(string $username, TokenInterface $token): UserInterface
    {
        $user = $token->getUser();
        if ($user instanceof UserInterface) {
            return $user;
        }

        try {
            $user = $this->userProvider->loadUserByUsername($username);

            return $user;
        } catch (UsernameNotFoundException $e) {
            $e->setUsername($username);
            throw $e;
        } catch (\Exception $e) {
            $e = new AuthenticationServiceException($e->getMessage(), 0, $e);
            $e->setToken($token);
            throw $e;
        }
    }
}
