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
        ->set('webauthn.cose.algorithm.RS256')
        ->class(RS256::class);

    $container
        ->set('webauthn.cose.algorithm.RS384')
        ->class(RS384::class);

    $container
        ->set('webauthn.cose.algorithm.RS512')
        ->class(RS512::class);

    $container
        ->set('webauthn.cose.algorithm.PS256')
        ->class(PS256::class);

    $container
        ->set('webauthn.cose.algorithm.PS384')
        ->class(PS384::class);

    $container
        ->set('webauthn.cose.algorithm.PS512')
        ->class(PS512::class);

    $container
        ->set('webauthn.cose.algorithm.ES256K')
        ->class(ES256K::class);

    $container
        ->set('webauthn.cose.algorithm.ES256')
        ->class(ES256::class);

    $container
        ->set('webauthn.cose.algorithm.ES384')
        ->class(ES384::class);

    $container
        ->set('webauthn.cose.algorithm.ES512')
        ->class(ES512::class);

    $container
        ->set('webauthn.cose.algorithm.ED256')
        ->class(Ed256::class);

    $container
        ->set('webauthn.cose.algorithm.ED512')
        ->class(Ed512::class);

    $container
        ->set('webauthn.cose.algorithm.Ed25519ph')
        ->class(Ed25519::class);
};
