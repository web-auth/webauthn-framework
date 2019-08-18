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

use CBOR\Decoder;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use function Symfony\Component\DependencyInjection\Loader\Configurator\ref;
use Webauthn\AttestationStatement;
use Webauthn\AuthenticationExtensions\ExtensionOutputCheckerHandler;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\Bundle\Service\PublicKeyCredentialCreationOptionsFactory;
use Webauthn\Bundle\Service\PublicKeyCredentialRequestOptionsFactory;
use Webauthn\PublicKeyCredentialLoader;
use Webauthn\PublicKeyCredentialSourceRepository;
use Webauthn\TokenBinding;

return function (ContainerConfigurator $container) {
    $container = $container->services()->defaults()
        ->private()
        ->autoconfigure()
        ->autowire();

    $container->set(AuthenticatorAttestationResponseValidator::class)
        ->public();
    $container->set(AuthenticatorAssertionResponseValidator::class)
        ->args([
            ref(PublicKeyCredentialSourceRepository::class),
            ref(Decoder::class),
            ref(TokenBinding\TokenBindingHandler::class),
            ref(ExtensionOutputCheckerHandler::class),
            ref('webauthn.cose.algorithm.manager'),
        ])
        ->public();
    $container->set(PublicKeyCredentialLoader::class)
        ->public();
    $container->set(PublicKeyCredentialCreationOptionsFactory::class)
        ->args([
            '%webauthn.creation_profiles%',
        ])
        ->public();
    $container->set(PublicKeyCredentialRequestOptionsFactory::class)
        ->args([
            '%webauthn.request_profiles%',
        ])
        ->public();

    $container->set(ExtensionOutputCheckerHandler::class);
    $container->set(AttestationStatement\AttestationObjectLoader::class);
    $container->set(AttestationStatement\AttestationStatementSupportManager::class);
    $container->set(AttestationStatement\NoneAttestationStatementSupport::class);

    $container->set(TokenBinding\IgnoreTokenBindingHandler::class);
    $container->set(TokenBinding\TokenBindingNotSupportedHandler::class);
};
