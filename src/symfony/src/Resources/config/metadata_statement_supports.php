<?php

declare(strict_types=1);

use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use function Symfony\Component\DependencyInjection\Loader\Configurator\service;
use Webauthn\AttestationStatement\AndroidKeyAttestationStatementSupport;
use Webauthn\AttestationStatement\AppleAttestationStatementSupport;
use Webauthn\AttestationStatement\CompoundAttestationStatementSupport;
use Webauthn\AttestationStatement\FidoU2FAttestationStatementSupport;
use Webauthn\AttestationStatement\PackedAttestationStatementSupport;
use Webauthn\AttestationStatement\TPMAttestationStatementSupport;
use Webauthn\MetadataService\CertificateChain\PhpCertificateChainValidator;

return static function (ContainerConfigurator $container): void {
    $service = $container->services()
        ->defaults()
        ->private()
        ->autoconfigure();

    $service
        ->set(AppleAttestationStatementSupport::class);
    $service
        ->set(TPMAttestationStatementSupport::class)
        ->args([service('webauthn.clock')])
    ;
    $service
        ->set(FidoU2FAttestationStatementSupport::class);
    $service
        ->set(CompoundAttestationStatementSupport::class);
    $service
        ->set(AndroidKeyAttestationStatementSupport::class);
    $service
        ->set(PackedAttestationStatementSupport::class)
        ->args([service('webauthn.cose.algorithm.manager')]);

    $service
        ->set(PhpCertificateChainValidator::class)
        ->args([service('webauthn.http_client'), service('webauthn.clock')]);
};
