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
use Symfony\Contracts\EventDispatcher\EventDispatcherInterface;
use Webauthn\AuthenticationExtensions\AuthenticationExtension;
use Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientInputs;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\Bundle\Event\PublicKeyCredentialCreationOptionsCreatedEvent;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialParameters;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;

final class PublicKeyCredentialCreationOptionsFactory
{
    /**
     * @var array
     */
    private $profiles;

    /**
     * @var EventDispatcherInterface
     */
    private $eventDispatcher;

    public function __construct(array $profiles, EventDispatcherInterface $eventDispatcher)
    {
        $this->profiles = $profiles;
        $this->eventDispatcher = $eventDispatcher;
    }

    public function create(string $key, PublicKeyCredentialUserEntity $userEntity, array $excludeCredentials = [], ?AuthenticatorSelectionCriteria $authenticatorSelection = null, ?string $attestationConveyance = null, ?AuthenticationExtensionsClientInputs $authenticationExtensionsClientInputs = null): PublicKeyCredentialCreationOptions
    {
        Assertion::keyExists($this->profiles, $key, sprintf('The profile with key "%s" does not exist.', $key));
        $profile = $this->profiles[$key];

        $options = new PublicKeyCredentialCreationOptions(
            $this->createRpEntity($profile),
            $userEntity,
            random_bytes($profile['challenge_length']),
            $this->createCredentialParameters($profile),
            $profile['timeout'],
            $excludeCredentials,
            $authenticatorSelection ?? $this->createAuthenticatorSelectionCriteria($profile),
            $attestationConveyance ?? $profile['attestation_conveyance'],
            $authenticationExtensionsClientInputs ?? $this->createExtensions($profile)
        );
        $this->eventDispatcher->dispatch(new PublicKeyCredentialCreationOptionsCreatedEvent($options));

        return $options;
    }

    private function createExtensions(array $profile): AuthenticationExtensionsClientInputs
    {
        $extensions = new AuthenticationExtensionsClientInputs();
        foreach ($profile['extensions'] as$k => $v) {
            $extensions->add(new AuthenticationExtension($k, $v));
        }

        return $extensions;
    }

    private function createAuthenticatorSelectionCriteria(array $profile): AuthenticatorSelectionCriteria
    {
        return new AuthenticatorSelectionCriteria(
            $profile['authenticator_selection_criteria']['attachment_mode'],
            $profile['authenticator_selection_criteria']['require_resident_key'],
            $profile['authenticator_selection_criteria']['user_verification']
        );
    }

    private function createRpEntity(array $profile): PublicKeyCredentialRpEntity
    {
        return new PublicKeyCredentialRpEntity($profile['rp']['name'], $profile['rp']['id'], $profile['rp']['icon']);
    }

    /**
     * @return PublicKeyCredentialParameters[]
     */
    private function createCredentialParameters(array $profile): array
    {
        $callback = function ($alg) {
            return new PublicKeyCredentialParameters(
                PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
                $alg
            );
        };

        return array_map($callback, $profile['public_key_credential_parameters']);
    }
}
