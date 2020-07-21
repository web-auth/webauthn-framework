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
use function Safe\sprintf;
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
     * @param array<PublicKeyCredentialDescriptor> $excludeCredentials
     */
    public function create(string $key, PublicKeyCredentialUserEntity $userEntity, array $excludeCredentials = [], ?AuthenticatorSelectionCriteria $authenticatorSelection = null, ?string $attestationConveyance = null, ?AuthenticationExtensionsClientInputs $authenticationExtensionsClientInputs = null): PublicKeyCredentialCreationOptions
    {
        Assertion::keyExists($this->profiles, $key, sprintf('The profile with key "%s" does not exist.', $key));
        $profile = $this->profiles[$key];

        $options = PublicKeyCredentialCreationOptions
            ::create(
                $this->createRpEntity($profile),
                $userEntity,
                random_bytes($profile['challenge_length']),
                $this->createCredentialParameters($profile)
            )
                ->excludeCredentials($excludeCredentials)
                ->setAuthenticatorSelection($authenticatorSelection ?? $this->createAuthenticatorSelectionCriteria($profile))
                ->setAttestation($attestationConveyance ?? $profile['attestation_conveyance'])
                ->setExtensions($authenticationExtensionsClientInputs ?? $this->createExtensions($profile))
                ->setTimeout($profile['timeout'])
        ;
        $this->eventDispatcher->dispatch(new PublicKeyCredentialCreationOptionsCreatedEvent($options));

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

    /**
     * @param array<string, mixed> $profile
     */
    private function createAuthenticatorSelectionCriteria(array $profile): AuthenticatorSelectionCriteria
    {
        return AuthenticatorSelectionCriteria::create()
            ->setAuthenticatorAttachment($profile['authenticator_selection_criteria']['attachment_mode'])
            ->setRequireResidentKey($profile['authenticator_selection_criteria']['require_resident_key'])
            ->setUserVerification($profile['authenticator_selection_criteria']['user_verification'])
            ->setResidentKey($profile['authenticator_selection_criteria']['resident_key'])
        ;
    }

    /**
     * @param array<string, mixed> $profile
     */
    private function createRpEntity(array $profile): PublicKeyCredentialRpEntity
    {
        return new PublicKeyCredentialRpEntity($profile['rp']['name'], $profile['rp']['id'], $profile['rp']['icon']);
    }

    /**
     * @param array<string, mixed> $profile
     *
     * @return array<PublicKeyCredentialParameters>
     */
    private function createCredentialParameters(array $profile): array
    {
        $callback = static function ($alg): PublicKeyCredentialParameters {
            return new PublicKeyCredentialParameters(
                PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
                $alg
            );
        };

        return array_map($callback, $profile['public_key_credential_parameters']);
    }
}
