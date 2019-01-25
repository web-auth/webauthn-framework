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

use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Webauthn\AttestationStatement;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\AuthenticationExtensions\ExtensionOutputCheckerHandler;
use Webauthn\Bundle\Service\PublicKeyCredentialCreationOptionsFactory;
use Webauthn\Bundle\Service\PublicKeyCredentialRequestOptionsFactory;
use Webauthn\PublicKeyCredentialLoader;
use Webauthn\TokenBinding;

return function (ContainerConfigurator $container) {
    $container = $container->services()->defaults()
        ->private()
        ->autoconfigure()
        ->autowire();

    $container->set(AuthenticatorAttestationResponseValidator::class)
        ->public();
    $container->set(AuthenticatorAssertionResponseValidator::class)
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
    $container->set(AttestationStatement\FidoU2FAttestationStatementSupport::class);
    $container->set(AttestationStatement\PackedAttestationStatementSupport::class);

    $container->set(TokenBinding\IgnoreTokenBindingHandler::class);
    $container->set(TokenBinding\TokenBindingNotSupportedHandler::class);
};
