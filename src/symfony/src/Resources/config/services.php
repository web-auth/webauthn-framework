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
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\PublicKeyCredentialLoader;

return function (ContainerConfigurator $container) {
    $container = $container->services()->defaults()
        ->private()
        ->autoconfigure()
        ->autowire();

    $container->set(AuthenticatorAttestationResponseValidator::class)
        ->public();
    $container->set(\Webauthn\AuthenticatorAssertionResponseValidator::class)
        ->public();
    $container->set(PublicKeyCredentialLoader::class)
        ->public();

    $container->set(AttestationStatement\AttestationObjectLoader::class);
    $container->set(AttestationStatement\AttestationStatementSupportManager::class);
    $container->set(AttestationStatement\NoneAttestationStatementSupport::class);
    $container->set(AttestationStatement\FidoU2FAttestationStatementSupport::class);
    $container->set(AttestationStatement\PackedAttestationStatementSupport::class);
};
