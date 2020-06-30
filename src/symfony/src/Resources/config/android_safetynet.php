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

use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\Algorithm\RS256;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Webauthn\AttestationStatement\AndroidSafetyNetAttestationStatementSupport;

return static function (ContainerConfigurator $container): void {
    $container = $container->services()->defaults()
        ->private()
        ->autoconfigure()
        ->autowire()
    ;

    if (class_exists(JWKFactory::class) && class_exists(RS256::class)) {
        $serviceConfigurator = $container->set(AndroidSafetyNetAttestationStatementSupport::class);
        $serviceConfigurator->call('setMaxAge', [
            '%webauthn.android_safetynet.max_age%',
        ]);
        $serviceConfigurator->call('setLeeway', [
            '%webauthn.android_safetynet.leeway%',
        ]);
    }
};
