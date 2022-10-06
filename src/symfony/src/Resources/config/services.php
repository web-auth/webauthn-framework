<?php

declare(strict_types=1);

use Psr\EventDispatcher\EventDispatcherInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ServerRequestFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Psr\Http\Message\UploadedFileFactoryInterface;
use Psr\Log\NullLogger;
use Symfony\Bridge\PsrHttpMessage\Factory\PsrHttpFactory;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use function Symfony\Component\DependencyInjection\Loader\Configurator\service;
use Symfony\Component\Serializer\SerializerInterface;
use Symfony\Component\Validator\Validator\ValidatorInterface;
use Webauthn\AttestationStatement\AttestationObjectLoader;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AttestationStatement\NoneAttestationStatementSupport;
use Webauthn\AuthenticationExtensions\ExtensionOutputCheckerHandler;
use Webauthn\AuthenticatorAssertionResponseValidator as BaseAuthenticatorAssertionResponseValidator;
use Webauthn\AuthenticatorAttestationResponseValidator as BaseAuthenticatorAttestationResponseValidator;
use Webauthn\Bundle\Controller\AssertionControllerFactory;
use Webauthn\Bundle\Controller\AttestationControllerFactory;
use Webauthn\Bundle\Controller\DummyControllerFactory;
use Webauthn\Bundle\Repository\DummyPublicKeyCredentialSourceRepository;
use Webauthn\Bundle\Repository\DummyPublicKeyCredentialUserEntityRepository;
use Webauthn\Bundle\Repository\PublicKeyCredentialUserEntityRepository;
use Webauthn\Bundle\Routing\Loader;
use Webauthn\Bundle\Service\AuthenticatorAssertionResponseValidator;
use Webauthn\Bundle\Service\AuthenticatorAttestationResponseValidator;
use Webauthn\Bundle\Service\PublicKeyCredentialCreationOptionsFactory;
use Webauthn\Bundle\Service\PublicKeyCredentialRequestOptionsFactory;
use Webauthn\Counter\ThrowExceptionIfInvalid;
use Webauthn\PublicKeyCredentialLoader;
use Webauthn\PublicKeyCredentialSourceRepository;
use Webauthn\TokenBinding\IgnoreTokenBindingHandler;
use Webauthn\TokenBinding\SecTokenBindingHandler;
use Webauthn\TokenBinding\TokenBindingHandler;
use Webauthn\TokenBinding\TokenBindingNotSupportedHandler;

return static function (ContainerConfigurator $container): void {
    $container = $container->services()
        ->defaults()
        ->private()
        ->autoconfigure();

    $container
        ->set(BaseAuthenticatorAttestationResponseValidator::class)
        ->class(AuthenticatorAttestationResponseValidator::class)
        ->args([
            service(AttestationStatementSupportManager::class),
            service(PublicKeyCredentialSourceRepository::class),
            service(TokenBindingHandler::class)->nullOnInvalid(),
            service(ExtensionOutputCheckerHandler::class),
            service(EventDispatcherInterface::class),
        ])
        ->public();
    $container
        ->set(BaseAuthenticatorAssertionResponseValidator::class)
        ->class(AuthenticatorAssertionResponseValidator::class)
        ->args([
            service(PublicKeyCredentialSourceRepository::class),
            service(TokenBindingHandler::class)->nullOnInvalid(),
            service(ExtensionOutputCheckerHandler::class),
            service('webauthn.cose.algorithm.manager'),
            service(EventDispatcherInterface::class),
        ])
        ->public();
    $container
        ->set(PublicKeyCredentialLoader::class)
        ->args([service(AttestationObjectLoader::class)])
        ->public();
    $container
        ->set(PublicKeyCredentialCreationOptionsFactory::class)
        ->args(['%webauthn.creation_profiles%', service(EventDispatcherInterface::class)])
        ->public();
    $container
        ->set(PublicKeyCredentialRequestOptionsFactory::class)
        ->args(['%webauthn.request_profiles%', service(EventDispatcherInterface::class)])
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
        ->deprecate(
            'web-auth/webauthn-symfony-bundle',
            '4.3.0',
            '%service_id% is deprecated since 4.3.0 and will be removed in 5.0.0'
        );
    $container
        ->set(TokenBindingNotSupportedHandler::class)
        ->deprecate(
            'web-auth/webauthn-symfony-bundle',
            '4.3.0',
            '%service_id% is deprecated since 4.3.0 and will be removed in 5.0.0'
        );
    $container
        ->set(SecTokenBindingHandler::class)
        ->deprecate(
            'web-auth/webauthn-symfony-bundle',
            '4.3.0',
            '%service_id% is deprecated since 4.3.0 and will be removed in 5.0.0'
        );

    $container
        ->set(ThrowExceptionIfInvalid::class)
        ->autowire(false);

    $container
        ->set(Loader::class)
        ->tag('routing.loader');

    $container
        ->set(AttestationControllerFactory::class)
        ->args([
            service('webauthn.http_message_factory'),
            service(SerializerInterface::class),
            service(ValidatorInterface::class),
            service(PublicKeyCredentialCreationOptionsFactory::class),
            service(PublicKeyCredentialLoader::class),
            service(BaseAuthenticatorAttestationResponseValidator::class),
            service(PublicKeyCredentialSourceRepository::class),
        ]);
    $container
        ->set(AssertionControllerFactory::class)
        ->args([
            service('webauthn.http_message_factory'),
            service(SerializerInterface::class),
            service(ValidatorInterface::class),
            service(PublicKeyCredentialRequestOptionsFactory::class),
            service(PublicKeyCredentialLoader::class),
            service(BaseAuthenticatorAssertionResponseValidator::class),
            service(PublicKeyCredentialUserEntityRepository::class),
            service(PublicKeyCredentialSourceRepository::class),
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
        ->set('webauthn.http_message_factory.default')
        ->class(PsrHttpFactory::class)
        ->args([
            service(ServerRequestFactoryInterface::class),
            service(StreamFactoryInterface::class),
            service(UploadedFileFactoryInterface::class),
            service(ResponseFactoryInterface::class),
        ]);

    $container
        ->set('webauthn.logger.default')
        ->class(NullLogger::class);

    $container
        ->alias('webauthn.http_client.default', ClientInterface::class);

    $container
        ->alias('webauthn.request_factory.default', RequestFactoryInterface::class);
};
