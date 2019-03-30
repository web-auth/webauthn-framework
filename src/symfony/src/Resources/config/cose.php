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

use Cose\Algorithm\Manager;
use Cose\Algorithm\Signature;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;

return function (ContainerConfigurator $container) {
    $container = $container->services()->defaults()
        ->private()
        ->autoconfigure()
        ->autowire();

    $container->set('webauthn.cose.algorithm.manager')
        ->class(Manager::class)
    ;

    $container->set('webauthn.cose.algoritm.RS1')
        ->class(Signature\RSA\RS1::class);
    $container->set('webauthn.cose.algoritm.RS256')
        ->class(Signature\RSA\RS256::class);
    $container->set('webauthn.cose.algoritm.RS384')
        ->class(Signature\RSA\RS384::class);
    $container->set('webauthn.cose.algoritm.RS512')
        ->class(Signature\RSA\RS512::class);

    $container->set('webauthn.cose.algoritm.ES256')
        ->class(Signature\ECDSA\ES256::class);
    $container->set('webauthn.cose.algoritm.ES384')
        ->class(Signature\ECDSA\ES384::class);
    $container->set('webauthn.cose.algoritm.ES512')
        ->class(Signature\ECDSA\ES512::class);

    $container->set('webauthn.cose.algoritm.EdDSA')
        ->class(Signature\EdDSA\EdDSA::class);
};
