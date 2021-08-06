<?php

declare(strict_types=1);

use Cose\Algorithm\Manager;
use Cose\Algorithm\Signature\ECDSA\ES256;
use Cose\Algorithm\Signature\ECDSA\ES256K;
use Cose\Algorithm\Signature\ECDSA\ES384;
use Cose\Algorithm\Signature\ECDSA\ES512;
use Cose\Algorithm\Signature\EdDSA\Ed25519;
use Cose\Algorithm\Signature\EdDSA\ED256;
use Cose\Algorithm\Signature\EdDSA\ED512;
use Cose\Algorithm\Signature\RSA\PS256;
use Cose\Algorithm\Signature\RSA\PS384;
use Cose\Algorithm\Signature\RSA\PS512;
use Cose\Algorithm\Signature\RSA\RS1;
use Cose\Algorithm\Signature\RSA\RS256;
use Cose\Algorithm\Signature\RSA\RS384;
/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2020 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

use Cose\Algorithm\Signature\RSA\RS512;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;

return static function (ContainerConfigurator $container): void {
    $container = $container->services()->defaults()
        ->private()
        ->autoconfigure()
        ->autowire()
    ;

    $container->set('webauthn.cose.algorithm.manager')
        ->class(Manager::class)
    ;

    $container->set('webauthn.cose.algoritm.RS1')
        ->class(RS1::class)
    ;
    $container->set('webauthn.cose.algoritm.RS256')
        ->class(RS256::class)
    ;
    $container->set('webauthn.cose.algoritm.RS384')
        ->class(RS384::class)
    ;
    $container->set('webauthn.cose.algoritm.RS512')
        ->class(RS512::class)
    ;

    $container->set('webauthn.cose.algoritm.PS256')
        ->class(PS256::class)
    ;
    $container->set('webauthn.cose.algoritm.PS384')
        ->class(PS384::class)
    ;
    $container->set('webauthn.cose.algoritm.PS512')
        ->class(PS512::class)
    ;

    $container->set('webauthn.cose.algoritm.ES256K')
        ->class(ES256K::class)
    ;
    $container->set('webauthn.cose.algoritm.ES256')
        ->class(ES256::class)
    ;
    $container->set('webauthn.cose.algoritm.ES384')
        ->class(ES384::class)
    ;
    $container->set('webauthn.cose.algoritm.ES512')
        ->class(ES512::class)
    ;

    $container->set('webauthn.cose.algoritm.ED256')
        ->class(ED256::class)
    ;
    $container->set('webauthn.cose.algoritm.ED512')
        ->class(ED512::class)
    ;
    $container->set('webauthn.cose.algoritm.Ed25519ph')
        ->class(Ed25519::class)
    ;
};
