<?php

declare(strict_types=1);

namespace Webauthn\Bundle\DataCollector;

use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use function Symfony\Component\DependencyInjection\Loader\Configurator\service;

return static function (ContainerConfigurator $container): void {
    $container = $container->services()
        ->defaults()
        ->private()
        ->autoconfigure();

    $container->set(WebauthnCollector::class)
        ->args([service('serializer')])
        ->tag('data_collector', [
            'id' => 'webauthn_collector',
            'template' => '@Webauthn/data_collector/template.html.twig',
        ]);
};
