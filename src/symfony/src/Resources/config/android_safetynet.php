<?php

declare(strict_types=1);

use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\Algorithm\RS256;
use Psr\Clock\ClockInterface;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Webauthn\AttestationStatement\AndroidSafetyNetAttestationStatementSupport;
use function Symfony\Component\DependencyInjection\Loader\Configurator\param;
use function Symfony\Component\DependencyInjection\Loader\Configurator\service;

return static function (ContainerConfigurator $container): void {
    $container = $container->services()
        ->defaults()
        ->private()
        ->autoconfigure();

    if (class_exists(JWKFactory::class) && class_exists(RS256::class)) {
        $container
            ->set(AndroidSafetyNetAttestationStatementSupport::class)
            ->args([service(ClockInterface::class)->nullOnInvalid()])
            ->call('setMaxAge', [param('webauthn.android_safetynet.max_age')])
            ->call('setLeeway', [param('webauthn.android_safetynet.leeway')]);
    }
};
