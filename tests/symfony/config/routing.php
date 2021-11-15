<?php

declare(strict_types=1);

use Symfony\Component\Routing\Loader\Configurator\RoutingConfigurator;
use Webauthn\Bundle\Tests\Functional\AdminController;
use Webauthn\Bundle\Tests\Functional\HomeController;
use Webauthn\Bundle\Tests\Functional\SecurityController;

return static function (RoutingConfigurator $routes): void {
    // Webauthn Dynamic routes
    $routes->import('@WebauthnBundle/Resources/config/routing.php');

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
