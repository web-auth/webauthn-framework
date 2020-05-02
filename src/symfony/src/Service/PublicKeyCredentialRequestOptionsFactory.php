<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2020 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Webauthn\Bundle\Service;

use Assert\Assertion;
use Symfony\Contracts\EventDispatcher\EventDispatcherInterface;
use Webauthn\AuthenticationExtensions\AuthenticationExtension;
use Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientInputs;
use Webauthn\Bundle\Event\PublicKeyCredentialRequestOptionsCreatedEvent;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialRequestOptions;

final class PublicKeyCredentialRequestOptionsFactory
{
    /**
     * @var array<string, mixed>
     */
    private $profiles;

    /**
     * @var EventDispatcherInterface
     */
    private $eventDispatcher;

    /**
     * @param array<string, mixed> $profiles
     */
    public function __construct(array $profiles, EventDispatcherInterface $eventDispatcher)
    {
        $this->profiles = $profiles;
        $this->eventDispatcher = $eventDispatcher;
    }

    /**
     * @param array<PublicKeyCredentialDescriptor> $allowCredentials
     */
    public function create(string $key, array $allowCredentials, ?string $userVerification = null, ?AuthenticationExtensionsClientInputs $authenticationExtensionsClientInputs = null): PublicKeyCredentialRequestOptions
    {
        Assertion::keyExists($this->profiles, $key, sprintf('The profile with key "%s" does not exist.', $key));
        $profile = $this->profiles[$key];

        $options = new PublicKeyCredentialRequestOptions(
            random_bytes($profile['challenge_length']),
            $profile['timeout'],
            $profile['rp_id'],
            $allowCredentials,
            $userVerification ?? $profile['user_verification'],
            $authenticationExtensionsClientInputs ?? $this->createExtensions($profile)
        );
        $this->eventDispatcher->dispatch(new PublicKeyCredentialRequestOptionsCreatedEvent($options));

        return $options;
    }

    /**
     * @param array<string, mixed> $profile
     */
    private function createExtensions(array $profile): AuthenticationExtensionsClientInputs
    {
        $extensions = new AuthenticationExtensionsClientInputs();
        foreach ($profile['extensions'] as$k => $v) {
            $extensions->add(new AuthenticationExtension($k, $v));
        }

        return $extensions;
    }
}
