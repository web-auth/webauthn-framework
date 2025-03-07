<?php

declare(strict_types=1);

use Psr\Log\NullLogger;
use Symfony\Component\Clock\NativeClock;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Contracts\HttpClient\HttpClientInterface;
use Webauthn\AttestationStatement\AttestationObjectLoader;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AttestationStatement\NoneAttestationStatementSupport;
use Webauthn\AuthenticationExtensions\ExtensionOutputCheckerHandler;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\Bundle\Controller\AssertionControllerFactory;
use Webauthn\Bundle\Controller\AttestationControllerFactory;
use Webauthn\Bundle\Controller\DummyControllerFactory;
use Webauthn\Bundle\Repository\DummyPublicKeyCredentialSourceRepository;
use Webauthn\Bundle\Repository\DummyPublicKeyCredentialUserEntityRepository;
use Webauthn\Bundle\Routing\Loader;
use Webauthn\Bundle\Service\DefaultFailureHandler;
use Webauthn\Bundle\Service\DefaultSuccessHandler;
use Webauthn\Bundle\Service\PublicKeyCredentialCreationOptionsFactory;
use Webauthn\Bundle\Service\PublicKeyCredentialRequestOptionsFactory;
use Webauthn\CeremonyStep\CeremonyStepManager;
use Webauthn\CeremonyStep\CeremonyStepManagerFactory;
use Webauthn\Counter\ThrowExceptionIfInvalid;
use Webauthn\Denormalizer\AttestationObjectDenormalizer;
use Webauthn\Denormalizer\AttestationStatementDenormalizer;
use Webauthn\Denormalizer\AttestedCredentialDataNormalizer;
use Webauthn\Denormalizer\AuthenticationExtensionNormalizer;
use Webauthn\Denormalizer\AuthenticationExtensionsDenormalizer;
use Webauthn\Denormalizer\AuthenticatorAssertionResponseDenormalizer;
use Webauthn\Denormalizer\AuthenticatorAttestationResponseDenormalizer;
use Webauthn\Denormalizer\AuthenticatorDataDenormalizer;
use Webauthn\Denormalizer\AuthenticatorResponseDenormalizer;
use Webauthn\Denormalizer\CollectedClientDataDenormalizer;
use Webauthn\Denormalizer\ExtensionDescriptorDenormalizer;
use Webauthn\Denormalizer\PublicKeyCredentialDenormalizer;
use Webauthn\Denormalizer\PublicKeyCredentialDescriptorNormalizer;
use Webauthn\Denormalizer\PublicKeyCredentialOptionsDenormalizer;
use Webauthn\Denormalizer\PublicKeyCredentialSourceDenormalizer;
use Webauthn\Denormalizer\PublicKeyCredentialUserEntityDenormalizer;
use Webauthn\Denormalizer\VerificationMethodANDCombinationsDenormalizer;
use Webauthn\Denormalizer\WebauthnSerializerFactory;
use Webauthn\SimpleFakeCredentialGenerator;
use function Symfony\Component\DependencyInjection\Loader\Configurator\param;
use function Symfony\Component\DependencyInjection\Loader\Configurator\service;

return static function (ContainerConfigurator $container): void {
    $service = $container->services()
        ->defaults()
        ->private()
        ->autoconfigure()
        ->autowire()
    ;

    $service
        ->set(CeremonyStepManagerFactory::class)
    ;

    $service
        ->set('webauthn.clock.default')
        ->class(NativeClock::class)
    ;

    $service
        ->set('webauthn.ceremony_step_manager.creation')
        ->class(CeremonyStepManager::class)
        ->factory([service(CeremonyStepManagerFactory::class), 'creationCeremony'])
    ;

    $service->set(SimpleFakeCredentialGenerator::class);

    $service
        ->set('webauthn.ceremony_step_manager.request')
        ->class(CeremonyStepManager::class)
        ->factory([service(CeremonyStepManagerFactory::class), 'requestCeremony'])
    ;

    $service
        ->set(AuthenticatorAttestationResponseValidator::class)
        ->args([service('webauthn.ceremony_step_manager.creation')])
        ->public();
    $service
        ->set(AuthenticatorAssertionResponseValidator::class)
        ->class(AuthenticatorAssertionResponseValidator::class)
        ->args([service('webauthn.ceremony_step_manager.request')])
        ->public();
    $service
        ->set(PublicKeyCredentialCreationOptionsFactory::class)
        ->args([param('webauthn.creation_profiles')])
        ->public();
    $service
        ->set(PublicKeyCredentialRequestOptionsFactory::class)
        ->args([param('webauthn.request_profiles')])
        ->public();

    $service->set(ExtensionOutputCheckerHandler::class);
    $service->set(AttestationObjectLoader::class);
    $service->set(AttestationStatementSupportManager::class);
    $service->set(NoneAttestationStatementSupport::class);

    $service
        ->set(ThrowExceptionIfInvalid::class)
        ->autowire(false);

    $service
        ->set(Loader::class)
        ->tag('routing.loader');

    $service->set(AttestationControllerFactory::class);
    $service->set(AssertionControllerFactory::class);

    $service
        ->set(DummyPublicKeyCredentialSourceRepository::class)
        ->autowire(false);
    $service
        ->set(DummyPublicKeyCredentialUserEntityRepository::class)
        ->autowire(false);

    $service
        ->set(DummyControllerFactory::class);

    $service
        ->set('webauthn.logger.default')
        ->class(NullLogger::class);

    $service
        ->alias('webauthn.http_client.default', HttpClientInterface::class);

    $service
        ->set(VerificationMethodANDCombinationsDenormalizer::class)
        ->tag('serializer.normalizer', [
            'priority' => 1024,
        ]);
    $service
        ->set(ExtensionDescriptorDenormalizer::class)
        ->tag('serializer.normalizer', [
            'priority' => 1024,
        ]);
    $service
        ->set(AttestationObjectDenormalizer::class)
        ->tag('serializer.normalizer', [
            'priority' => 1024,
        ]);
    $service
        ->set(AttestationStatementDenormalizer::class)
        ->args([service(AttestationStatementSupportManager::class)])
        ->tag('serializer.normalizer', [
            'priority' => 1024,
        ]);
    $service
        ->set(AuthenticationExtensionNormalizer::class)
        ->tag('serializer.normalizer', [
            'priority' => 1024,
        ]);
    $service
        ->set(PublicKeyCredentialDescriptorNormalizer::class)
        ->tag('serializer.normalizer', [
            'priority' => 1024,
        ]);
    $service
        ->set(AttestedCredentialDataNormalizer::class)
        ->tag('serializer.normalizer', [
            'priority' => 1024,
        ]);
    $service
        ->set(AuthenticationExtensionsDenormalizer::class)
        ->tag('serializer.normalizer', [
            'priority' => 1024,
        ]);
    $service
        ->set(AuthenticatorAssertionResponseDenormalizer::class)
        ->tag('serializer.normalizer', [
            'priority' => 1024,
        ]);
    $service
        ->set(AuthenticatorAttestationResponseDenormalizer::class)
        ->tag('serializer.normalizer', [
            'priority' => 1024,
        ]);
    $service
        ->set(AuthenticatorDataDenormalizer::class)
        ->tag('serializer.normalizer', [
            'priority' => 1024,
        ]);
    $service
        ->set(AuthenticatorResponseDenormalizer::class)
        ->tag('serializer.normalizer', [
            'priority' => 1024,
        ]);
    $service
        ->set(CollectedClientDataDenormalizer::class)
        ->tag('serializer.normalizer', [
            'priority' => 1024,
        ]);
    $service
        ->set(PublicKeyCredentialDenormalizer::class)
        ->tag('serializer.normalizer', [
            'priority' => 1024,
        ]);
    $service
        ->set(PublicKeyCredentialOptionsDenormalizer::class)
        ->tag('serializer.normalizer', [
            'priority' => 1024,
        ]);
    $service
        ->set(PublicKeyCredentialSourceDenormalizer::class)
        ->tag('serializer.normalizer', [
            'priority' => 1024,
        ]);
    $service
        ->set(PublicKeyCredentialUserEntityDenormalizer::class)
        ->tag('serializer.normalizer', [
            'priority' => 1024,
        ]);
    $service->set(WebauthnSerializerFactory::class);
    $service->set(DefaultFailureHandler::class);
    $service->set(DefaultSuccessHandler::class);
};
