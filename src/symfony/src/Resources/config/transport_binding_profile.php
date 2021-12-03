<?php

declare(strict_types=1);

use Symfony\Bridge\PsrHttpMessage\HttpMessageFactoryInterface;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use function Symfony\Component\DependencyInjection\Loader\Configurator\ref;
use Webauthn\Bundle\Controller\AssertionResponseControllerFactory;
use Webauthn\Bundle\Controller\AttestationResponseControllerFactory;

return static function (ContainerConfigurator $container): void {
    $container = $container->services()
        ->defaults()
        ->private()
        ->autoconfigure()
        ->bind(HttpMessageFactoryInterface::class, ref('webauthn.transport_binding_profile.http_message_factory'))
        ->autowire()
    ;

    $container->set(AttestationResponseControllerFactory::class);
    $container->set(AssertionResponseControllerFactory::class);
};
