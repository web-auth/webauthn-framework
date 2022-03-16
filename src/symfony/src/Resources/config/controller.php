<?php

declare(strict_types=1);

use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use function Symfony\Component\DependencyInjection\Loader\Configurator\service;
use Symfony\Component\Serializer\SerializerInterface;
use Symfony\Component\Validator\Validator\ValidatorInterface;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\Bundle\Controller\AttestationControllerFactory;
use Webauthn\Bundle\Service\DefaultFailureHandler;
use Webauthn\Bundle\Service\DefaultSuccessHandler;
use Webauthn\Bundle\Service\PublicKeyCredentialCreationOptionsFactory;
use Webauthn\PublicKeyCredentialLoader;
use Webauthn\PublicKeyCredentialSourceRepository;

return static function (ContainerConfigurator $container): void {
    $container = $container->services()
        ->defaults()
        ->private()
        ->autoconfigure()
    ;

    $container
        ->set(AttestationControllerFactory::class)
        ->args([
            service('webauthn.http.factory'),
            service(SerializerInterface::class),
            service(ValidatorInterface::class),
            service(PublicKeyCredentialCreationOptionsFactory::class),
            service(PublicKeyCredentialLoader::class),
            service(AuthenticatorAttestationResponseValidator::class),
            service(PublicKeyCredentialSourceRepository::class),
        ])
    ;
    $container->set(DefaultFailureHandler::class);
    $container->set(DefaultSuccessHandler::class);
};
