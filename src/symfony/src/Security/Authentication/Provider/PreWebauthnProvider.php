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

namespace Webauthn\Bundle\Security\Authentication\Provider;

use Assert\Assertion;
use Symfony\Component\Security\Core\Authentication\Provider\AuthenticationProviderInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\AuthenticationServiceException;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use Symfony\Component\Security\Core\User\UserCheckerInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Webauthn\Bundle\Model\CanHaveRegisteredSecurityDevices;
use Webauthn\Bundle\Security\Authentication\Token\PreWebauthnToken;

class PreWebauthnProvider implements AuthenticationProviderInterface
{
    private $userChecker;
    private $providerKey;
    private $userProvider;

    public function __construct(UserCheckerInterface $userChecker, UserProviderInterface $userProvider, string $providerKey)
    {
        Assertion::notEmpty($providerKey, '$providerKey must not be empty.');

        $this->userChecker = $userChecker;
        $this->providerKey = $providerKey;
        $this->userProvider = $userProvider;
    }

    public function authenticate(TokenInterface $token)
    {
        if (!$this->supports($token)) {
            throw new AuthenticationException('The token is not supported by this authentication provider.');
        }

        return $this->processWithPreWebauthnToken($token);
    }

    public function supports(TokenInterface $token)
    {
        return $token instanceof PreWebauthnToken && $this->providerKey === $token->getProviderKey();
    }

    private function processWithPreWebauthnToken(PreWebauthnToken $token): PreWebauthnToken
    {
        $username = $token->getUsername();
        if (empty($username)) {
            throw new AuthenticationServiceException('retrieveUser() must return a UserInterface.');
        }

        $user = $this->retrieveUser($username, $token);

        if (!$user instanceof CanHaveRegisteredSecurityDevices || empty($user->getSecurityDeviceCredentialIds())) {
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
            $user->getRoles()
        );
        $authenticatedToken->setUser($user);
        $authenticatedToken->setAuthenticated(true);

        return $authenticatedToken;
    }

    private function retrieveUser($username, TokenInterface $token): UserInterface
    {
        $user = $token->getUser();
        if ($user instanceof UserInterface) {
            return $user;
        }

        try {
            $user = $this->userProvider->loadUserByUsername($username);
            if (!$user instanceof UserInterface) {
                throw new UsernameNotFoundException('The user provider must return a UserInterface object.');
            }

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
