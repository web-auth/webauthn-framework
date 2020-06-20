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
use function Symfony\Component\DependencyInjection\Loader\Configurator\ref;
use Webauthn\AttestationStatement\AndroidSafetyNetAttestationStatementSupport;

return static function (ContainerConfigurator $container): void {
    $container = $container->services()->defaults()
        ->private()
        ->autoconfigure()
        ->autowire()
    ;

    if (class_exists(JWKFactory::class) && class_exists(RS256::class)) {
        $container->set(AndroidSafetyNetAttestationStatementSupport::class)
            ->args([
                ref('webauthn.android_safetynet.http_client')->nullOnInvalid(),
                '%webauthn.android_safetynet.api_key%',
                ref('webauthn.android_safetynet.request_factory')->nullOnInvalid(),
                '%webauthn.android_safetynet.leeway%',
                '%webauthn.android_safetynet.max_age%',
            ])
        ;
    }
};
