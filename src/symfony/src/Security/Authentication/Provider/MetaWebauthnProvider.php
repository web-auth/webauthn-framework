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
use Symfony\Component\Security\Core\User\UserCheckerInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;

class MetaWebauthnProvider implements AuthenticationProviderInterface
{
    private $preWebauthnProvider;
    private $webauthnProvider;

    public function __construct(UserCheckerInterface $userChecker, UserProviderInterface $userProvider, string $providerKey)
    {
        Assertion::notEmpty($providerKey, '$providerKey must not be empty.');

        $this->preWebauthnProvider = new PreWebauthnProvider($userChecker, $userProvider, $providerKey);
        $this->webauthnProvider = new WebauthnProvider($providerKey);
    }

    public function authenticate(TokenInterface $token)
    {
        switch (true) {
            case $this->preWebauthnProvider->supports($token):
                return $this->preWebauthnProvider->authenticate($token);
            case $this->webauthnProvider->supports($token):
                return $this->webauthnProvider->authenticate($token);
            default:
                throw new AuthenticationException('The token is not supported by this authentication provider.');
        }
    }

    public function supports(TokenInterface $token)
    {
        return $this->preWebauthnProvider->supports($token) || $this->webauthnProvider->supports($token);
    }
}
