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

namespace Webauthn\Bundle\Security\Authentication\Token;

use Assert\Assertion;
use Symfony\Component\Security\Core\Authentication\Token\AbstractToken;

class WebauthnToken extends AbstractToken
{
    private $credentials;
    private $providerKey;

    public function __construct(string $username, string $credentials, string $providerKey, array $roles = [])
    {
        parent::__construct($roles);
        Assertion::notEmpty($providerKey, '$providerKey must not be empty.');

        $this->setUser($username);
        $this->credentials = $credentials;
        $this->providerKey = $providerKey;

        parent::setAuthenticated(\count($roles) > 0);
    }

    public function getCredentials()
    {
        return $this->credentials;
    }

    public function getProviderKey(): string
    {
        return $this->providerKey;
    }
}
