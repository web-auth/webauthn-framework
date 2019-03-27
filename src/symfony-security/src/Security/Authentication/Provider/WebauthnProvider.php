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
use Webauthn\SecurityBundle\Security\Authentication\Token\WebauthnToken;

class WebauthnProvider implements AuthenticationProviderInterface
{
    /**
     * @var string
     */
    private $providerKey;

    public function __construct(string $providerKey)
    {
        Assertion::notEmpty($providerKey, '$providerKey must not be empty.');

        $this->providerKey = $providerKey;
    }

    /**
     * {@inheritdoc}
     */
    public function authenticate(TokenInterface $token): WebauthnToken
    {
        Assertion::isInstanceOf($token, WebauthnToken::class, 'The token is not supported by this authentication provider.');
        Assertion::eq($this->providerKey, $token->getProviderKey(), 'The token is not supported by this authentication provider.');

        return $this->processWithWebauthnToken($token);
    }

    /**
     * {@inheritdoc}
     */
    public function supports(TokenInterface $token)
    {
        return $token instanceof WebauthnToken && $this->providerKey === $token->getProviderKey();
    }

    private function processWithWebauthnToken(WebauthnToken $token): WebauthnToken
    {
        $token->setAuthenticated(true);

        return $token;
    }
}
