<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Webauthn\Bundle\Routing\Loader;
use Webauthn\ConformanceToolset\Controller\AssertionResponseControllerFactory;
use Webauthn\ConformanceToolset\Controller\AttestationResponseControllerFactory;

return function (ContainerConfigurator $container) {
    $container = $container->services()->defaults()
        ->private()
        ->autoconfigure()
        ->autowire();

    $container->set(Loader::class)
        ->tag('routing.loader');

    $container->set(AttestationResponseControllerFactory::class);
    $container->set(AssertionResponseControllerFactory::class);
};
