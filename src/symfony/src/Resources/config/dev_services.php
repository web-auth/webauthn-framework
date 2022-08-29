<?php

declare(strict_types=1);

namespace Webauthn\Bundle\DataCollector;

use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;

return static function (ContainerConfigurator $container): void {
    $container = $container->services()
        ->defaults()
        ->private()
        ->autoconfigure();

    $container->set(WebauthnCollector::class)
        ->tag('data_collector', [
            'id' => 'webauthn_collector',
            'template' => '@Webauthn/data_collector/template.html.twig',
        ]);
};
