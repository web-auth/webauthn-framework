<?php

declare(strict_types=1);

use Psr\Cache\CacheItemPoolInterface;
use Psr\Log\NullLogger;
use Symfony\Component\Clock\NativeClock;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use function Symfony\Component\DependencyInjection\Loader\Configurator\param;
use function Symfony\Component\DependencyInjection\Loader\Configurator\service;
use Symfony\Contracts\HttpClient\HttpClientInterface;
use Webauthn\AttestationStatement\AttestationObjectLoader;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AttestationStatement\NoneAttestationStatementSupport;
use Webauthn\AuthenticationExtensions\ExtensionOutputCheckerHandler;
use Webauthn\AuthenticationExtensions\PaymentExtensionOutputChecker;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\Bundle\Controller\AssertionControllerFactory;
use Webauthn\Bundle\Controller\AttestationControllerFactory;
use Webauthn\Bundle\Controller\DummyControllerFactory;
use Webauthn\Bundle\Policy\ClientOverridePolicy;
use Webauthn\Bundle\Repository\DummyPublicKeyCredentialSourceRepository;
use Webauthn\Bundle\Repository\DummyPublicKeyCredentialUserEntityRepository;
use Webauthn\Bundle\Routing\Loader;
use Webauthn\Bundle\Service\DefaultFailureHandler;
use Webauthn\Bundle\Service\DefaultSuccessHandler;
use Webauthn\Bundle\Service\PublicKeyCredentialCreationOptionsFactory;
use Webauthn\Bundle\Service\PublicKeyCredentialRequestOptionsFactory;
use Webauthn\Bundle\Service\WebauthnOptionsResponse;
use Webauthn\Bundle\Service\WebauthnResponseVerifier;
use Webauthn\Bundle\Service\WebauthnSignalFactory;
use Webauthn\Bundle\Service\WebauthnSignalResponse;
use Webauthn\CeremonyStep\CeremonyStepManager;
use Webauthn\CeremonyStep\CeremonyStepManagerFactory;
use Webauthn\ClientDataCollector\ClientDataCollectorManager;
use Webauthn\ClientDataCollector\PaymentClientDataCollector;
use Webauthn\ClientDataCollector\WebauthnAuthenticationCollector;
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
use Webauthn\Denormalizer\BrowserBoundPublicKeyDenormalizer;
use Webauthn\Denormalizer\BrowserBoundSignatureDenormalizer;
use Webauthn\Denormalizer\CollectedClientAdditionalPaymentDataDenormalizer;
use Webauthn\Denormalizer\CollectedClientDataDenormalizer;
use Webauthn\Denormalizer\CollectedClientPaymentDataDenormalizer;
use Webauthn\Denormalizer\ExtensionDescriptorDenormalizer;
use Webauthn\Denormalizer\PaymentCredentialInstrumentDenormalizer;
use Webauthn\Denormalizer\PaymentCurrencyAmountDenormalizer;
use Webauthn\Denormalizer\PaymentEntityLogoDenormalizer;
use Webauthn\Denormalizer\PublicKeyCredentialDenormalizer;
use Webauthn\Denormalizer\PublicKeyCredentialDescriptorNormalizer;
use Webauthn\Denormalizer\PublicKeyCredentialOptionsDenormalizer;
use Webauthn\Denormalizer\PublicKeyCredentialRpEntityDenormalizer;
use Webauthn\Denormalizer\PublicKeyCredentialSourceDenormalizer;
use Webauthn\Denormalizer\PublicKeyCredentialUserEntityDenormalizer;
use Webauthn\Denormalizer\SignalAllAcceptedCredentialsDenormalizer;
use Webauthn\Denormalizer\SignalCurrentUserDetailsDenormalizer;
use Webauthn\Denormalizer\SignalUnknownCredentialDenormalizer;
use Webauthn\Denormalizer\UrlNormalizer;
use Webauthn\Denormalizer\VerificationMethodANDCombinationsDenormalizer;
use Webauthn\Denormalizer\WebauthnSerializerFactory;
use Webauthn\SimpleFakeCredentialGenerator;

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

    $service
        ->set('webauthn.ceremony_step_manager.conditional_creation')
        ->class(CeremonyStepManager::class)
        ->factory([service(CeremonyStepManagerFactory::class), 'conditionalCreateCeremony'])
    ;

    $service->set(SimpleFakeCredentialGenerator::class)
        ->args([service(CacheItemPoolInterface::class)->nullOnInvalid(), param('kernel.secret')])
    ;

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
        ->set('webauthn.authenticator_attestation_response_validator.conditional_creation')
        ->class(AuthenticatorAttestationResponseValidator::class)
        ->args([service('webauthn.ceremony_step_manager.conditional_creation')])
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
    $service->set(PaymentExtensionOutputChecker::class);

    // SPC: collectors that validate clientDataJSON depending on its `type`
    // ("webauthn.get"/"webauthn.create" vs "payment.get").
    $service->set(WebauthnAuthenticationCollector::class);
    $service->set(PaymentClientDataCollector::class);
    $service
        ->set(ClientDataCollectorManager::class)
        ->args([[service(WebauthnAuthenticationCollector::class), service(PaymentClientDataCollector::class)]]);

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
        ->set(UrlNormalizer::class)
        ->args([service('router')])
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
        ->set(PublicKeyCredentialRpEntityDenormalizer::class)
        ->tag('serializer.normalizer', [
            'priority' => 1024,
        ]);
    $service
        ->set(PublicKeyCredentialUserEntityDenormalizer::class)
        ->tag('serializer.normalizer', [
            'priority' => 1024,
        ]);
    $service
        ->set(SignalAllAcceptedCredentialsDenormalizer::class)
        ->tag('serializer.normalizer', [
            'priority' => 1024,
        ]);
    $service
        ->set(SignalCurrentUserDetailsDenormalizer::class)
        ->tag('serializer.normalizer', [
            'priority' => 1024,
        ]);
    $service
        ->set(SignalUnknownCredentialDenormalizer::class)
        ->tag('serializer.normalizer', [
            'priority' => 1024,
        ]);
    $service
        ->set(CollectedClientPaymentDataDenormalizer::class)
        ->tag('serializer.normalizer', [
            'priority' => 1024,
        ]);
    $service
        ->set(CollectedClientAdditionalPaymentDataDenormalizer::class)
        ->tag('serializer.normalizer', [
            'priority' => 1024,
        ]);
    $service
        ->set(PaymentCurrencyAmountDenormalizer::class)
        ->tag('serializer.normalizer', [
            'priority' => 1024,
        ]);
    $service
        ->set(PaymentCredentialInstrumentDenormalizer::class)
        ->tag('serializer.normalizer', [
            'priority' => 1024,
        ]);
    $service
        ->set(PaymentEntityLogoDenormalizer::class)
        ->tag('serializer.normalizer', [
            'priority' => 1024,
        ]);
    $service
        ->set(BrowserBoundSignatureDenormalizer::class)
        ->tag('serializer.normalizer', [
            'priority' => 1024,
        ]);
    $service
        ->set(BrowserBoundPublicKeyDenormalizer::class)
        ->tag('serializer.normalizer', [
            'priority' => 1024,
        ]);
    $service->set(WebauthnSerializerFactory::class);
    $service->set(DefaultFailureHandler::class);
    $service->set(DefaultSuccessHandler::class);

    // WebAuthn L3 §5.1.10 signal helpers — autowired so applications can
    // request them from a custom SuccessHandler / controller.
    $service->set(WebauthnSignalFactory::class)->public();
    $service->set(WebauthnSignalResponse::class)->public();

    $service->set(WebauthnOptionsResponse::class)->public();

    $service
        ->set(WebauthnResponseVerifier::class)
        ->arg(
            '$conditionalAttestationValidator',
            service('webauthn.authenticator_attestation_response_validator.conditional_creation')
        )
        ->public();

    $service
        ->set(ClientOverridePolicy::class)
        ->args([param('webauthn.client_override_policy')])
        ->public();
};
