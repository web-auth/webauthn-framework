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
use Webauthn\AuthenticationExtensions\AuthenticationExtension;
use Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientInputs;
use Webauthn\AuthenticatorSelectionCriteria;
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

    public function __construct(array $profiles)
    {
        $this->profiles = $profiles;
    }

    public function create(string $key, PublicKeyCredentialUserEntity $userEntity, array $excludeCredentials = [], ?AuthenticatorSelectionCriteria $authenticatorSelection = null, ?string $attestation = null): PublicKeyCredentialCreationOptions
    {
        Assertion::keyExists($this->profiles, $key, \Safe\sprintf('The profile with key "%s" does not exist.', $key));
        $profile = $this->profiles[$key];

        return new PublicKeyCredentialCreationOptions(
            $this->createRpEntity($profile),
            $userEntity,
            random_bytes($profile['challenge_length']),
            $this->createCredentialParameters($profile),
            $profile['timeout'],
            $excludeCredentials,
            $authenticatorSelection ?? $this->createAuthenticatorSelectionCriteria($profile),
            $attestation ?? $profile['attestation_conveyance'],
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
