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
use Webauthn\Bundle\Security\Authentication\Token\WebauthnToken;

class WebauthnProvider implements AuthenticationProviderInterface
{
    private $providerKey;

    public function __construct(string $providerKey)
    {
        Assertion::notEmpty($providerKey, '$providerKey must not be empty.');

        $this->providerKey = $providerKey;
    }

    public function authenticate(TokenInterface $token)
    {
        if (!$this->supports($token)) {
            throw new AuthenticationException('The token is not supported by this authentication provider.');
        }

        return $this->processWithWebauthnToken($token);
    }

    public function supports(TokenInterface $token)
    {
        return $token instanceof WebauthnToken && $this->providerKey === $token->getProviderKey();
    }

    private function processWithWebauthnToken(WebauthnToken $token)
    {
        $token->setAuthenticated(true);

        return $token;
    }
}
