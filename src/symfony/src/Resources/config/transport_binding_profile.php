<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2020 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

use Symfony\Bridge\PsrHttpMessage\HttpMessageFactoryInterface;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use function Symfony\Component\DependencyInjection\Loader\Configurator\ref;
use Webauthn\ConformanceToolset\Controller\AssertionResponseControllerFactory;
use Webauthn\ConformanceToolset\Controller\AttestationResponseControllerFactory;

return static function (ContainerConfigurator $container): void {
    $container = $container->services()->defaults()
        ->private()
        ->autoconfigure()
        ->bind(
            HttpMessageFactoryInterface::class,
            ref('webauthn.transport_binding_profile.http_message_factory')
        )
        ->autowire()
    ;

    $container->set(AttestationResponseControllerFactory::class);
    $container->set(AssertionResponseControllerFactory::class);
};
