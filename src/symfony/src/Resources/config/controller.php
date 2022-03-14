<?php

declare(strict_types=1);

use Symfony\Bridge\PsrHttpMessage\HttpMessageFactoryInterface;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use function Symfony\Component\DependencyInjection\Loader\Configurator\service;
use Webauthn\Bundle\Controller\AttestationControllerFactory;
use Webauthn\Bundle\Service\DefaultFailureHandler;
use Webauthn\Bundle\Service\DefaultSuccessHandler;

return static function (ContainerConfigurator $container): void {
    $container = $container->services()
        ->defaults()
        ->private()
        ->autoconfigure()
        ->bind(HttpMessageFactoryInterface::class, service('webauthn.controller.http_message_factory'))
        ->autowire()
    ;

    $container->set(AttestationControllerFactory::class);
    $container->set(DefaultFailureHandler::class);
    $container->set(DefaultSuccessHandler::class);
};
