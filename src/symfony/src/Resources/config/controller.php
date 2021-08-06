<?php

declare(strict_types=1);

use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Webauthn\Bundle\Controller\AttestationResponseControllerFactory;
use Webauthn\Bundle\Service\DefaultFailureHandler;
use Webauthn\Bundle\Service\DefaultSuccessHandler;

return static function (ContainerConfigurator $container): void {
    $container = $container->services()->defaults()
        ->private()
        ->autoconfigure()
        ->autowire()
    ;

    $container->set(AttestationResponseControllerFactory::class);
    $container->set(DefaultFailureHandler::class);
    $container->set(DefaultSuccessHandler::class);
};
