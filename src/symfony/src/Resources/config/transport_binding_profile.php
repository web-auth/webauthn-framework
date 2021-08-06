<?php

declare(strict_types=1);

use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Webauthn\ConformanceToolset\Controller\AssertionResponseControllerFactory;
use Webauthn\ConformanceToolset\Controller\AttestationResponseControllerFactory;

return static function (ContainerConfigurator $container): void {
    $container = $container->services()->defaults()
        ->private()
        ->autoconfigure()
        ->autowire()
    ;

    $container->set(AttestationResponseControllerFactory::class);
    $container->set(AssertionResponseControllerFactory::class);
};
