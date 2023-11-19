<?php

declare(strict_types=1);

use Lcobucci\Clock\SystemClock;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Log\NullLogger;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\Serializer\SerializerInterface;
use Symfony\Component\Validator\Validator\ValidatorInterface;
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
use Webauthn\Bundle\Repository\PublicKeyCredentialUserEntityRepositoryInterface;
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
use Webauthn\Denormalizer\AuthenticationExtensionsDenormalizer;
use Webauthn\Denormalizer\AuthenticatorAssertionResponseDenormalizer;
use Webauthn\Denormalizer\AuthenticatorAttestationResponseDenormalizer;
use Webauthn\Denormalizer\AuthenticatorDataDenormalizer;
use Webauthn\Denormalizer\AuthenticatorResponseDenormalizer;
use Webauthn\Denormalizer\CollectedClientDataDenormalizer;
use Webauthn\Denormalizer\PublicKeyCredentialDenormalizer;
use Webauthn\Denormalizer\PublicKeyCredentialOptionsDenormalizer;
use Webauthn\Denormalizer\PublicKeyCredentialSourceDenormalizer;
use Webauthn\Denormalizer\PublicKeyCredentialUserEntityDenormalizer;
use Webauthn\Denormalizer\WebauthnSerializerFactory;
use Webauthn\MetadataService\Denormalizer\ExtensionDescriptorDenormalizer;
use Webauthn\MetadataService\Denormalizer\MetadataStatementSerializerFactory;
use Webauthn\PublicKeyCredentialLoader;
use Webauthn\PublicKeyCredentialSourceRepository;
use Webauthn\TokenBinding\IgnoreTokenBindingHandler;
use Webauthn\TokenBinding\SecTokenBindingHandler;
use Webauthn\TokenBinding\TokenBindingNotSupportedHandler;
use function Symfony\Component\DependencyInjection\Loader\Configurator\param;
use function Symfony\Component\DependencyInjection\Loader\Configurator\service;

return static function (ContainerConfigurator $container): void {
    $deprecationData = [
        'web-auth/webauthn-symfony-bundle',
        '4.3.0',
        '%service_id% is deprecated since 4.3.0 and will be removed in 5.0.0',
    ];
    $container = $container->services()
        ->defaults()
        ->private()
        ->autoconfigure();

    $container
        ->set('webauthn.clock.default')
        ->class(SystemClock::class)
        ->factory([SystemClock::class, 'fromSystemTimezone'])
    ;

    $container
        ->set(CeremonyStepManagerFactory::class)
    ;

    $container
        ->set('webauthn.ceremony_step_manager.creation')
        ->class(CeremonyStepManager::class)
        ->factory([service(CeremonyStepManagerFactory::class), 'creationCeremony'])
        ->args([param('webauthn.secured_relying_party_ids')])
    ;

    $container
        ->set('webauthn.ceremony_step_manager.request')
        ->class(CeremonyStepManager::class)
        ->factory([service(CeremonyStepManagerFactory::class), 'requestCeremony'])
        ->args([param('webauthn.secured_relying_party_ids')])
    ;

    $container
        ->set(AuthenticatorAttestationResponseValidator::class)
        ->args([null, null, null, null, null, service('webauthn.ceremony_step_manager.creation')])
        ->public();
    $container
        ->set(AuthenticatorAssertionResponseValidator::class)
        ->class(AuthenticatorAssertionResponseValidator::class)
        ->args([null, null, null, null, null, service('webauthn.ceremony_step_manager.request')])
        ->public();
    $container
        ->set(PublicKeyCredentialLoader::class)
        ->deprecate(
            'web-auth/webauthn-symfony-bundle',
            '4.8.0',
            '%service_id% is deprecated since 4.8.0 and will be removed in 5.0.0',
        )
        ->args([null, service(SerializerInterface::class)])
        ->public();
    $container
        ->set(PublicKeyCredentialCreationOptionsFactory::class)
        ->args([param('webauthn.creation_profiles')])
        ->public();
    $container
        ->set(PublicKeyCredentialRequestOptionsFactory::class)
        ->args([param('webauthn.request_profiles')])
        ->public();

    $container
        ->set(ExtensionOutputCheckerHandler::class);
    $container
        ->set(AttestationObjectLoader::class)
        ->args([service(AttestationStatementSupportManager::class)]);
    $container
        ->set(AttestationStatementSupportManager::class);
    $container
        ->set(NoneAttestationStatementSupport::class);

    $container
        ->set(IgnoreTokenBindingHandler::class)
        ->deprecate(...$deprecationData);
    $container
        ->set(TokenBindingNotSupportedHandler::class)
        ->deprecate(...$deprecationData);
    $container
        ->set(SecTokenBindingHandler::class)
        ->deprecate(...$deprecationData);

    $container
        ->set(ThrowExceptionIfInvalid::class)
        ->autowire(false);

    $container
        ->set(Loader::class)
        ->tag('routing.loader');

    $container
        ->set(AttestationControllerFactory::class)
        ->args([
            service(SerializerInterface::class),
            service(ValidatorInterface::class),
            service(PublicKeyCredentialCreationOptionsFactory::class),
            null,
            service(AuthenticatorAttestationResponseValidator::class),
            service(PublicKeyCredentialSourceRepository::class)->nullOnInvalid(),
        ]);
    $container
        ->set(AssertionControllerFactory::class)
        ->args([
            service(SerializerInterface::class),
            service(ValidatorInterface::class),
            service(PublicKeyCredentialRequestOptionsFactory::class),
            null,
            service(AuthenticatorAssertionResponseValidator::class),
            service(PublicKeyCredentialUserEntityRepositoryInterface::class),
            service(PublicKeyCredentialSourceRepository::class)->nullOnInvalid(),
        ]);

    $container
        ->set(DummyPublicKeyCredentialSourceRepository::class)
        ->autowire(false);
    $container
        ->set(DummyPublicKeyCredentialUserEntityRepository::class)
        ->autowire(false);

    $container
        ->set(DummyControllerFactory::class);

    $container
        ->set('webauthn.logger.default')
        ->class(NullLogger::class);

    $container
        ->alias('webauthn.http_client.default', HttpClientInterface::class);

    $container
        ->alias('webauthn.request_factory.default', RequestFactoryInterface::class);

    $container
        ->set(ExtensionDescriptorDenormalizer::class)
        ->tag('serializer.normalizer', [
            'priority' => 1024,
        ]);
    $container
        ->set(AttestationObjectDenormalizer::class)
        ->tag('serializer.normalizer', [
            'priority' => 1024,
        ]);
    $container
        ->set(AttestationStatementDenormalizer::class)
        ->args([service(AttestationStatementSupportManager::class)])
        ->tag('serializer.normalizer', [
            'priority' => 1024,
        ]);
    $container
        ->set(AuthenticationExtensionsDenormalizer::class)
        ->tag('serializer.normalizer', [
            'priority' => 1024,
        ]);
    $container
        ->set(AuthenticatorAssertionResponseDenormalizer::class)
        ->tag('serializer.normalizer', [
            'priority' => 1024,
        ]);
    $container
        ->set(AuthenticatorAttestationResponseDenormalizer::class)
        ->tag('serializer.normalizer', [
            'priority' => 1024,
        ]);
    $container
        ->set(AuthenticatorDataDenormalizer::class)
        ->tag('serializer.normalizer', [
            'priority' => 1024,
        ]);
    $container
        ->set(AuthenticatorResponseDenormalizer::class)
        ->tag('serializer.normalizer', [
            'priority' => 1024,
        ]);
    $container
        ->set(CollectedClientDataDenormalizer::class)
        ->tag('serializer.normalizer', [
            'priority' => 1024,
        ]);
    $container
        ->set(PublicKeyCredentialDenormalizer::class)
        ->tag('serializer.normalizer', [
            'priority' => 1024,
        ]);
    $container
        ->set(PublicKeyCredentialOptionsDenormalizer::class)
        ->tag('serializer.normalizer', [
            'priority' => 1024,
        ]);
    $container
        ->set(PublicKeyCredentialSourceDenormalizer::class)
        ->tag('serializer.normalizer', [
            'priority' => 1024,
        ]);
    $container
        ->set(PublicKeyCredentialUserEntityDenormalizer::class)
        ->tag('serializer.normalizer', [
            'priority' => 1024,
        ]);
    $container->set(WebauthnSerializerFactory::class)
        ->args([service(AttestationStatementSupportManager::class)])
    ;
    $container->set(MetadataStatementSerializerFactory::class);
    $container->set(DefaultFailureHandler::class);
    $container->set(DefaultSuccessHandler::class);
};
