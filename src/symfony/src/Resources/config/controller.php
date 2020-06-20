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
use Webauthn\Bundle\Controller\AttestationResponseControllerFactory;
use Webauthn\Bundle\Service\DefaultFailureHandler;
use Webauthn\Bundle\Service\DefaultSuccessHandler;

return static function (ContainerConfigurator $container): void {
    $container = $container->services()->defaults()
        ->private()
        ->autoconfigure()
        ->bind(
            HttpMessageFactoryInterface::class,
            ref('webauthn.controller.http_message_factory')
        )
        ->autowire()
    ;

    $container->set(AttestationResponseControllerFactory::class);
    $container->set(DefaultFailureHandler::class);
    $container->set(DefaultSuccessHandler::class);
};
