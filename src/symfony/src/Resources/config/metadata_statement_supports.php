<?php

declare(strict_types=1);

use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use function Symfony\Component\DependencyInjection\Loader\Configurator\service;
use Webauthn\AttestationStatement\AndroidKeyAttestationStatementSupport;
use Webauthn\AttestationStatement\AppleAttestationStatementSupport;
use Webauthn\AttestationStatement\FidoU2FAttestationStatementSupport;
use Webauthn\AttestationStatement\PackedAttestationStatementSupport;
use Webauthn\AttestationStatement\TPMAttestationStatementSupport;
use Webauthn\MetadataService\CertificateChain\PhpCertificateChainValidator;

return static function (ContainerConfigurator $container): void {
    $container = $container->services()
        ->defaults()
        ->private()
        ->autoconfigure();

    $container
        ->set(AppleAttestationStatementSupport::class);
    $container
        ->set(TPMAttestationStatementSupport::class)
        ->args([
            service('webauthn.clock')->nullOnInvalid()
        ])
    ;
    $container
        ->set(FidoU2FAttestationStatementSupport::class);
    $container
        ->set(AndroidKeyAttestationStatementSupport::class);
    $container
        ->set(PackedAttestationStatementSupport::class)
        ->args([service('webauthn.cose.algorithm.manager')]);

    $container
        ->set(PhpCertificateChainValidator::class)
        ->args([
            service('webauthn.http_client'),
            service('webauthn.request_factory'),
            service('webauthn.clock'),
        ]);
};
