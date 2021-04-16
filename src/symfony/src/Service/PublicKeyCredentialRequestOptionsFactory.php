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
use JetBrains\PhpStorm\Pure;
use function Safe\sprintf;
use Symfony\Contracts\EventDispatcher\EventDispatcherInterface;
use Webauthn\AuthenticationExtensions\AuthenticationExtension;
use Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientInputs;
use Webauthn\Bundle\Event\PublicKeyCredentialRequestOptionsCreatedEvent;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialRequestOptions;

final class PublicKeyCredentialRequestOptionsFactory
{
    #[Pure]
    public function __construct(private array $profiles, private EventDispatcherInterface $eventDispatcher)
    {
    }

    /**
     * @param PublicKeyCredentialDescriptor[] $allowCredentials
     */
    public function create(string $key, array $allowCredentials, ?string $userVerification = null, ?AuthenticationExtensionsClientInputs $authenticationExtensionsClientInputs = null): PublicKeyCredentialRequestOptions
    {
        Assertion::keyExists($this->profiles, $key, sprintf('The profile with key "%s" does not exist.', $key));
        $profile = $this->profiles[$key];

        $options = PublicKeyCredentialRequestOptions
            ::create(random_bytes($profile['challenge_length']))
                ->setRpId($profile['rp_id'])
                ->setUserVerification($userVerification ?? $profile['user_verification'])
                ->allowCredentials($allowCredentials)
                ->setExtensions($authenticationExtensionsClientInputs ?? $this->createExtensions($profile))
                ->setTimeout($profile['timeout'])
        ;
        $this->eventDispatcher->dispatch(new PublicKeyCredentialRequestOptionsCreatedEvent($options));

        return $options;
    }

    private function createExtensions(array $profile): AuthenticationExtensionsClientInputs
    {
        $extensions = new AuthenticationExtensionsClientInputs();
        foreach ($profile['extensions'] as $k => $v) {
            $extensions->add(new AuthenticationExtension($k, $v));
        }

        return $extensions;
    }
}
