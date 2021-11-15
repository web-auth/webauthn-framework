<?php

declare(strict_types=1);

use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use function Symfony\Component\DependencyInjection\Loader\Configurator\ref;
use Webauthn\CertificateChainChecker\CertificateChainChecker;

return static function (ContainerConfigurator $container): void {
    $container = $container->services()
        ->defaults()
        ->private()
        ->autoconfigure()
        ->autowire()
    ;

    $container->set(CertificateChainChecker::class)
        ->args([
            ref('webauthn.certificate_chain_checker.http_client'),
            ref('webauthn.certificate_chain_checker.request_factory'),
        ])
    ;
};
