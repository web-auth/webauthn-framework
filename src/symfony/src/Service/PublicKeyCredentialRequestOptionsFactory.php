<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2019 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Webauthn\Bundle\Service;

use Assert\Assertion;
use function Safe\sprintf;
use Webauthn\AuthenticationExtensions\AuthenticationExtension;
use Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientInputs;
use Webauthn\PublicKeyCredentialRequestOptions;

final class PublicKeyCredentialRequestOptionsFactory
{
    /**
     * @var array
     */
    private $profiles;

    public function __construct(array $profiles)
    {
        $this->profiles = $profiles;
    }

    public function create(string $key, array $allowCredentials, ?string $userVerification = null): PublicKeyCredentialRequestOptions
    {
        Assertion::keyExists($this->profiles, $key, sprintf('The profile with key "%s" does not exist.', $key));
        $profile = $this->profiles[$key];

        return new PublicKeyCredentialRequestOptions(
            random_bytes($profile['challenge_length']),
            $profile['timeout'],
            $profile['rp_id'],
            $allowCredentials,
            $userVerification ?? $profile['user_verification'],
            $this->createExtensions($profile)
        );
    }

    private function createExtensions(array $profile): AuthenticationExtensionsClientInputs
    {
        $extensions = new AuthenticationExtensionsClientInputs();
        foreach ($profile['extensions'] as$k => $v) {
            $extensions->add(new AuthenticationExtension($k, $v));
        }

        return $extensions;
    }
}
