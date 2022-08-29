<?php

declare(strict_types=1);

use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\Algorithm\RS256;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Webauthn\AttestationStatement\AndroidSafetyNetAttestationStatementSupport;

return static function (ContainerConfigurator $container): void {
    $container = $container->services()
        ->defaults()
        ->private()
        ->autoconfigure();

    if (class_exists(JWKFactory::class) && class_exists(RS256::class)) {
        $container
            ->set(AndroidSafetyNetAttestationStatementSupport::class)
            ->call('setMaxAge', ['%webauthn.android_safetynet.max_age%'])
            ->call('setLeeway', ['%webauthn.android_safetynet.leeway%']);
    }
};
