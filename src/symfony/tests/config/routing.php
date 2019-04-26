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

use Symfony\Component\Routing\Loader\Configurator\RoutingConfigurator;
use Webauthn\Bundle\Tests\Functional\AdminController;
use Webauthn\Bundle\Tests\Functional\HomeController;
use Webauthn\Bundle\Tests\Functional\SecurityController;

return function (RoutingConfigurator $routes) {
    $routes->import('.', 'webauthn');

    // Security
    $routes->add('app_login', '/login')
        ->controller([SecurityController::class, 'login'])
        ->methods(['POST'])
    ;

    $routes->add('app_login_options', '/login/options')
        ->controller([SecurityController::class, 'options'])
        ->methods(['POST'])
    ;

    $routes->add('app_logout', '/logout')
        ->controller([SecurityController::class, 'logout'])
        ->methods(['POST'])
    ;

    // Home
    $routes->add('app_home', '/')
        ->controller([HomeController::class, 'home'])
        ->methods(['GET'])
    ;

    // Admin
    $routes->add('app_admin', '/admin')
        ->controller([AdminController::class, 'admin'])
        ->methods(['GET'])
    ;
};
