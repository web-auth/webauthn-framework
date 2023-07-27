<?php

declare(strict_types=1);

use Cose\Algorithm\Manager;
use Cose\Algorithm\Signature\ECDSA\ES256;
use Cose\Algorithm\Signature\ECDSA\ES256K;
use Cose\Algorithm\Signature\ECDSA\ES384;
use Cose\Algorithm\Signature\ECDSA\ES512;
use Cose\Algorithm\Signature\EdDSA\Ed25519;
use Cose\Algorithm\Signature\EdDSA\Ed256;
use Cose\Algorithm\Signature\EdDSA\Ed512;
use Cose\Algorithm\Signature\RSA\PS256;
use Cose\Algorithm\Signature\RSA\PS384;
use Cose\Algorithm\Signature\RSA\PS512;
use Cose\Algorithm\Signature\RSA\RS1;
use Cose\Algorithm\Signature\RSA\RS256;
use Cose\Algorithm\Signature\RSA\RS384;
use Cose\Algorithm\Signature\RSA\RS512;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;

return static function (ContainerConfigurator $container): void {
    $deprecationData = [
        'web-auth/webauthn-symfony-bundle',
        '4.7.0',
        'The "%alias_id%" service alias is deprecated, use "%service_id%" instead.',
    ];
    $container = $container->services()
        ->defaults()
        ->private()
        ->autoconfigure();

    $container
        ->set('webauthn.cose.algorithm.manager')
        ->class(Manager::class);

    $container
        ->set('webauthn.cose.algorithm.RS1')
        ->class(RS1::class);
    $container
        ->alias('webauthn.cose.algoritm.RS1', 'webauthn.cose.algorithm.RS1')
        ->deprecate(...$deprecationData)
    ;

    $container
        ->set('webauthn.cose.algorithm.RS256')
        ->class(RS256::class);
    $container
        ->alias('webauthn.cose.algoritm.RS256', 'webauthn.cose.algorithm.RS256')
        ->deprecate(...$deprecationData)
    ;

    $container
        ->set('webauthn.cose.algorithm.RS384')
        ->class(RS384::class);
    $container
        ->alias('webauthn.cose.algoritm.RS384', 'webauthn.cose.algorithm.RS384')
        ->deprecate(...$deprecationData)
    ;

    $container
        ->set('webauthn.cose.algorithm.RS512')
        ->class(RS512::class);
    $container
        ->alias('webauthn.cose.algoritm.RS512', 'webauthn.cose.algorithm.RS512')
        ->deprecate(...$deprecationData)
    ;

    $container
        ->set('webauthn.cose.algorithm.PS256')
        ->class(PS256::class);
    $container
        ->alias('webauthn.cose.algoritm.PS256', 'webauthn.cose.algorithm.PS256')
        ->deprecate(...$deprecationData)
    ;

    $container
        ->set('webauthn.cose.algorithm.PS384')
        ->class(PS384::class);
    $container
        ->alias('webauthn.cose.algoritm.PS384', 'webauthn.cose.algorithm.PS384')
        ->deprecate(...$deprecationData)
    ;

    $container
        ->set('webauthn.cose.algorithm.PS512')
        ->class(PS512::class);
    $container
        ->alias('webauthn.cose.algoritm.PS512', 'webauthn.cose.algorithm.PS512')
        ->deprecate(...$deprecationData)
    ;

    $container
        ->set('webauthn.cose.algorithm.ES256K')
        ->class(ES256K::class);
    $container
        ->alias('webauthn.cose.algoritm.ES256K', 'webauthn.cose.algorithm.ES256K')
        ->deprecate(...$deprecationData)
    ;

    $container
        ->set('webauthn.cose.algorithm.ES256')
        ->class(ES256::class);
    $container
        ->alias('webauthn.cose.algoritm.ES256', 'webauthn.cose.algorithm.ES256')
        ->deprecate(...$deprecationData)
    ;

    $container
        ->set('webauthn.cose.algorithm.ES384')
        ->class(ES384::class);
    $container
        ->alias('webauthn.cose.algoritm.ES384', 'webauthn.cose.algorithm.ES384')
        ->deprecate(...$deprecationData)
    ;

    $container
        ->set('webauthn.cose.algorithm.ES512')
        ->class(ES512::class);
    $container
        ->alias('webauthn.cose.algoritm.ES512', 'webauthn.cose.algorithm.ES512')
        ->deprecate(...$deprecationData)
    ;

    $container
        ->set('webauthn.cose.algorithm.ED256')
        ->class(Ed256::class);
    $container
        ->alias('webauthn.cose.algoritm.ED256', 'webauthn.cose.algorithm.ED256')
        ->deprecate(...$deprecationData)
    ;

    $container
        ->set('webauthn.cose.algorithm.ED512')
        ->class(Ed512::class);
    $container
        ->alias('webauthn.cose.algoritm.ED512', 'webauthn.cose.algorithm.ED512')
        ->deprecate(...$deprecationData)
    ;

    $container
        ->set('webauthn.cose.algorithm.Ed25519ph')
        ->class(Ed25519::class);
    $container
        ->alias('webauthn.cose.algoritm.Ed25519ph', 'webauthn.cose.algorithm.Ed25519ph')
        ->deprecate(...$deprecationData)
    ;
};
