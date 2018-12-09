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

class PreWebauthnToken extends AbstractToken
{
    private $rememberMe;
    private $providerKey;

    public function __construct(string $username, string $providerKeyDescriptor, bool $rememberMe, array $roles = [])
    {
        parent::__construct($roles);
        Assertion::notEmpty($providerKeyDescriptor, '$providerKey must not be empty.');

        $this->setUser($username);
        $this->rememberMe = $rememberMe;
        $this->providerKey = $providerKeyDescriptor;
    }

    public function getCredentials()
    {
        return;
    }

    public function getProviderKey(): string
    {
        return $this->providerKey;
    }

    public function isRememberMe(): bool
    {
        return $this->rememberMe;
    }

    public function serialize()
    {
        return serialize([$this->rememberMe, $this->providerKey, parent::serialize()]);
    }

    public function unserialize($serialized)
    {
        list($this->rememberMe, $this->providerKey, $parentStr) = unserialize($serialized);

        parent::unserialize($parentStr);
    }
}
