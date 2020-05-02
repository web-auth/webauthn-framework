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

use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use function Symfony\Component\DependencyInjection\Loader\Configurator\ref;
use Webauthn\AttestationStatement;

return static function (ContainerConfigurator $container): void {
    $container = $container->services()->defaults()
        ->private()
        ->autoconfigure()
        ->autowire();

    $container->set(AttestationStatement\TPMAttestationStatementSupport::class);
    $container->set(AttestationStatement\FidoU2FAttestationStatementSupport::class);
    $container->set(AttestationStatement\AndroidKeyAttestationStatementSupport::class);
    $container->set(AttestationStatement\PackedAttestationStatementSupport::class)
        ->args([
            ref('webauthn.cose.algorithm.manager'),
        ]);
};
