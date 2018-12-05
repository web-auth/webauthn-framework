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
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialRequestOptions;

class WebauthnToken extends AbstractToken
{
    private $providerKey;
    private $publicKeyCredentialRequestOptions;
    private $publicKeyCredential;

    public function __construct(string $username, PublicKeyCredentialRequestOptions $publicKeyCredentialRequestOptions, PublicKeyCredential $publicKeyCredential, string $providerKey, array $roles = [])
    {
        parent::__construct($roles);
        Assertion::notEmpty($providerKey, '$providerKey must not be empty.');

        $this->setUser($username);
        $this->providerKey = $providerKey;
        $this->publicKeyCredentialRequestOptions = $publicKeyCredentialRequestOptions;
        $this->publicKeyCredential = $publicKeyCredential;
    }

    public function getPublicKeyCredentialRequestOptions(): PublicKeyCredentialRequestOptions
    {
        return $this->publicKeyCredentialRequestOptions;
    }

    public function getCredentials()
    {
        return $this->publicKeyCredential;
    }

    public function getProviderKey(): string
    {
        return $this->providerKey;
    }
}
