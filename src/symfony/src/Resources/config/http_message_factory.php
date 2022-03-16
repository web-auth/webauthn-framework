<?php

declare(strict_types=1);

use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ServerRequestFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Psr\Http\Message\UploadedFileFactoryInterface;
use Symfony\Bridge\PsrHttpMessage\Factory\PsrHttpFactory;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use function Symfony\Component\DependencyInjection\Loader\Configurator\service;

return static function (ContainerConfigurator $container): void {
    $container = $container->services()
        ->defaults()
        ->private()
        ->autoconfigure()
    ;

    $container
        ->set('webauthn.http.factory')
        ->class(PsrHttpFactory::class)
        ->args([
            service(ServerRequestFactoryInterface::class),
            service(StreamFactoryInterface::class),
            service(UploadedFileFactoryInterface::class),
            service(ResponseFactoryInterface::class),
        ])
    ;
};
