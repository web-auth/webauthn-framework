<?php

declare(strict_types=1);

use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use function Symfony\Component\DependencyInjection\Loader\Configurator\service;
use Webauthn\CertificateChainChecker\CertificateChainChecker;
use Webauthn\CertificateChainChecker\OpenSSLCertificateChainChecker;

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
