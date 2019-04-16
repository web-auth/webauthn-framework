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

use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use function Symfony\Component\DependencyInjection\Loader\Configurator\ref;
use Webauthn\MetadataService\MetadataServiceCaller;

return function (ContainerConfigurator $container) {
    $container = $container->services()->defaults()
        ->private()
        ->autoconfigure()
        ->autowire();

    $container->set(MetadataServiceCaller::class)
        ->public()
        ->args([
            ref('webauthn.metadata_service.http_client'),
            ref('webauthn.metadata_service.request_factory'),
            '%webauthn.metadata_service.token%',
        ]);
};
