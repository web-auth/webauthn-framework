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

use Psr\Http\Message\RequestFactoryInterface;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use function Symfony\Component\DependencyInjection\Loader\Configurator\ref;
use Symfony\Component\HttpClient\Psr18Client;
use Webauthn\AttestationStatement;

return function (ContainerConfigurator $container) {
    $container = $container->services()->defaults()
        ->private()
        ->autoconfigure()
        ->autowire();

    $container->set('webauthn.android_safetynet.default_http_client')
        ->class(Psr18Client::class);

    $container->set(AttestationStatement\AndroidSafetyNetAttestationStatementSupport::class)
        ->args([
            ref('webauthn.android_safetynet.http_client'),
            '%webauthn.android_safetynet.api_key%',
            ref(RequestFactoryInterface::class)->nullOnInvalid(),
            '%webauthn.android_safetynet.leeway%',
            '%webauthn.android_safetynet.max_age%',
            null,
        ]);
};
