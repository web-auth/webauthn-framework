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
use Webauthn\CertificateChainChecker\OpenSSLCertificateChainChecker;
use function Symfony\Component\DependencyInjection\Loader\Configurator\service;
use Webauthn\CertificateChainChecker\CertificateChainChecker;

return static function (ContainerConfigurator $container): void {
    $container = $container->services()->defaults()
        ->private()
        ->autoconfigure()
        ->autowire()
    ;

    $container->set(CertificateChainChecker::class)
        ->class(OpenSSLCertificateChainChecker::class)
        ->args([
            service('webauthn.certificate_chain_checker.http_client'),
            service('webauthn.certificate_chain_checker.request_factory'),
        ])
    ;
};
