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
use Symfony\Component\Security\Core\Role\SwitchUserRole;
use Symfony\Component\Security\Core\User\UserCheckerInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Webauthn\Bundle\Model\CanHaveRegisteredSecurityDevices;
use Webauthn\Bundle\Security\Authentication\Token\PreWebauthnToken;
use Webauthn\Bundle\Security\Authentication\Token\WebauthnToken;

class WebauthnProvider implements AuthenticationProviderInterface
{
    private $hideUserNotFoundExceptions;
    private $userChecker;
    private $providerKey;

    public function __construct(UserCheckerInterface $userChecker, string $providerKey)
    {
        Assertion::notEmpty($providerKey, '$providerKey must not be empty.');

        $this->userChecker = $userChecker;
        $this->providerKey = $providerKey;
    }

    public function authenticate(TokenInterface $token)
    {
        dump($token);
        if (!$this->supports($token)) {
            throw new AuthenticationException('The token is not supported by this authentication provider.');
        }

        $username = $token->getUsername();
        if ('' === $username || null === $username) {
            $username = AuthenticationProviderInterface::USERNAME_NONE_PROVIDED;
        }

        try {
            $user = $this->retrieveUser($username);
        } catch (UsernameNotFoundException $e) {
            $e->setUsername($username);

            throw $e;
        }

        if (!$user instanceof CanHaveRegisteredSecurityDevices) {
            throw new AuthenticationServiceException('retrieveUser() must return a UserInterface.');
        }

        /*try {
            $this->userChecker->checkPreAuth($user);
            $this->checkAuthentication($user, $token);
            $this->userChecker->checkPostAuth($user);
        } catch (BadCredentialsException $e) {
            if ($this->hideUserNotFoundExceptions) {
                throw new BadCredentialsException('Bad credentials.', 0, $e);
            }

            throw $e;
        }

        $authenticatedToken = new WebauthnToken($user, $token->getCredentials(), $this->providerKey, $this->getRoles($user, $token));
        $authenticatedToken->setAttributes($token->getAttributes());

        return $authenticatedToken;*/
    }

    public function supports(TokenInterface $token)
    {
        return ($token instanceof PreWebauthnToken || $token instanceof WebauthnToken) && $this->providerKey === $token->getProviderKey();
    }

    private function getRoles(UserInterface $user, TokenInterface $token)
    {
        $roles = $user->getRoles();

        foreach ($token->getRoles() as $role) {
            if ($role instanceof SwitchUserRole) {
                $roles[] = $role;

                break;
            }
        }

        return $roles;
    }

    private function retrieveUser($username): UserInterface
    {
    }

    private function checkAuthentication(UserInterface $user, string $token): void
    {
    }
}
