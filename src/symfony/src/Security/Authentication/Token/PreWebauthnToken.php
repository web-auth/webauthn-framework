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
use Webauthn\AuthenticationExtensions\AuthenticationExtension;
use Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientInputs;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialRequestOptions;

class PreWebauthnToken extends AbstractToken
{
    private $publicKeyCredentialRequestOptions;
    private $providerKey;

    public function __construct(string $username, PublicKeyCredentialRequestOptions $publicKeyCredentialRequestOptions, string $providerKey, array $roles = [])
    {
        parent::__construct($roles);
        Assertion::notEmpty($providerKey, '$providerKey must not be empty.');

        $this->setUser($username);
        $this->publicKeyCredentialRequestOptions = $publicKeyCredentialRequestOptions;
        $this->providerKey = $providerKey;
    }

    public function getCredentials()
    {
        return $this->publicKeyCredentialRequestOptions;
    }

    public function getProviderKey(): string
    {
        return $this->providerKey;
    }

    public function serialize()
    {
        return serialize([\Safe\json_encode($this->publicKeyCredentialRequestOptions), $this->providerKey, parent::serialize()]);
    }

    public function unserialize($serialized)
    {
        list($publicKeyCredentialRequestOptions, $this->providerKey, $parentStr) = unserialize($serialized);
        $data = \Safe\json_decode($publicKeyCredentialRequestOptions, true);
        $rpId = $data['rpId'] ?? null;
        $challenge = \Safe\base64_decode($data['challenge'], true);
        $userVerification = $data['userVerification'] ?? null;
        $allowCredentials = [];
        if (isset($data['allowCredentials'])) {
            foreach ($data['allowCredentials'] as $credential) {
                $allowCredentials[] = new PublicKeyCredentialDescriptor(
                    $credential['type'],
                    \Safe\base64_decode($credential['id'], true),
                    $credential['tranports'] ?? []
                );
            }
        }
        $timeout = $data['timeout'] ?? null;
        $extensions = new AuthenticationExtensionsClientInputs();
        if (isset($data['extensions'])) {
            foreach ($data['extensions'] as $k => $v) {
                $extensions->add(new AuthenticationExtension($k, $v));
            }
        }
        $this->publicKeyCredentialRequestOptions = new PublicKeyCredentialRequestOptions($challenge, $timeout, $rpId, $allowCredentials, $userVerification, $extensions);

        parent::unserialize($parentStr);
    }
}
