<?php

declare(strict_types=1);

use Psr\Log\LoggerInterface;
use Symfony\Bridge\PsrHttpMessage\HttpMessageFactoryInterface;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
 use function Symfony\Component\DependencyInjection\Loader\Configurator\service;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\Security\Core\Authentication\AuthenticationManagerInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\User\UserCheckerInterface;
use Symfony\Component\Security\Http\HttpUtils;
use Symfony\Component\Security\Http\Session\SessionAuthenticationStrategyInterface;
use Symfony\Component\Serializer\SerializerInterface;
use Symfony\Component\Validator\Validator\ValidatorInterface;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\Bundle\Repository\PublicKeyCredentialUserEntityRepository;
use Webauthn\Bundle\Security\Authentication\Provider\WebauthnProvider;
use Webauthn\Bundle\Security\EntryPoint\WebauthnEntryPoint;
use Webauthn\Bundle\Security\Firewall\CreationListener;
use Webauthn\Bundle\Security\Firewall\RequestListener;
use Webauthn\Bundle\Security\Firewall\WebauthnListener;
use Webauthn\Bundle\Security\Handler\DefaultCreationOptionsHandler;
use Webauthn\Bundle\Security\Handler\DefaultFailureHandler;
use Webauthn\Bundle\Security\Handler\DefaultRequestOptionsHandler;
use Webauthn\Bundle\Security\Handler\DefaultSuccessHandler;
use Webauthn\Bundle\Security\Storage\SessionStorage;
use Webauthn\Bundle\Security\Voter\IsUserPresentVoter;
use Webauthn\Bundle\Security\Voter\IsUserVerifiedVoter;
use Webauthn\Bundle\Service\PublicKeyCredentialCreationOptionsFactory;
use Webauthn\Bundle\Service\PublicKeyCredentialRequestOptionsFactory;
use Webauthn\PublicKeyCredentialLoader;
use Webauthn\PublicKeyCredentialSourceRepository;

return static function (ContainerConfigurator $container): void {
    $container->services()->set(WebauthnProvider::class)
        ->private()
        ->arg(0, service(UserCheckerInterface::class))
    ;

    $container->services()->set('security.authentication.listener.webauthn')
        ->class(WebauthnListener::class)
        ->abstract()
        ->private()
        ->args([
            '', // HTTP Message Factory
            service(SerializerInterface::class),
            service(ValidatorInterface::class),
            service(PublicKeyCredentialRequestOptionsFactory::class),
            service(PublicKeyCredentialSourceRepository::class),
            service(PublicKeyCredentialUserEntityRepository::class),
            service(PublicKeyCredentialLoader::class),
            service(AuthenticatorAssertionResponseValidator::class),
            service(TokenStorageInterface::class),
            service(AuthenticationManagerInterface::class),
            service(SessionAuthenticationStrategyInterface::class),
            service(HttpUtils::class),
            '', // Provider key
            [], // Options
            null, // Authentication success handler
            null, // Authentication failure handler
            null, // Request Options handler
            null, // Request Options Storage
            service(LoggerInterface::class)->nullOnInvalid(),
            service(EventDispatcherInterface::class)->nullOnInvalid(),
        ])
        ->tag('monolog.logger', ['channel' => 'security'])
    ;

    $container->services()->set('security.authentication.listener.webauthn')
        ->class(WebauthnListener::class)
        ->abstract()
        ->private()
        ->args([
            service(HttpUtils::class),
            service('webauthn.logger')->nullOnInvalid(),
            null, // Request Listener
            null, // Creation Listener
            [], // Options
        ])
        ->tag('monolog.logger', ['channel' => 'security'])
    ;

    $container->services()->set('security.authentication.listener.webauthn.request')
        ->class(RequestListener::class)
        ->abstract()
        ->private()
        ->args([
            service(HttpMessageFactoryInterface::class),
            service(SerializerInterface::class),
            service(ValidatorInterface::class),
            service(PublicKeyCredentialRequestOptionsFactory::class),
            service(PublicKeyCredentialSourceRepository::class),
            service(PublicKeyCredentialUserEntityRepository::class),
            service(PublicKeyCredentialLoader::class),
            service(AuthenticatorAssertionResponseValidator::class),
            service(TokenStorageInterface::class),
            service(AuthenticationManagerInterface::class),
            service(SessionAuthenticationStrategyInterface::class),
            '', // Provider key
            [], // Options
            null, // Authentication success handler
            null, // Authentication failure handler
            null, // Options handler
            null, // Options Storage
            service('webauthn.logger')->nullOnInvalid(),
            service(EventDispatcherInterface::class)->nullOnInvalid(),
            [], // Secured Relying Party IDs
        ])
        ->tag('monolog.logger', ['channel' => 'security'])
    ;

    $container->services()->set('security.authentication.listener.webauthn.creation')
        ->class(CreationListener::class)
        ->abstract()
        ->private()
        ->args([
            service(HttpMessageFactoryInterface::class),
            service(SerializerInterface::class),
            service(ValidatorInterface::class),
            service(PublicKeyCredentialCreationOptionsFactory::class),
            service(PublicKeyCredentialSourceRepository::class),
            service(PublicKeyCredentialUserEntityRepository::class),
            service(PublicKeyCredentialLoader::class),
            service(AuthenticatorAttestationResponseValidator::class),
            service(TokenStorageInterface::class),
            service(AuthenticationManagerInterface::class),
            service(SessionAuthenticationStrategyInterface::class),
            '', // Provider key
            [], // Options
            null, // Authentication success handler
            null, // Authentication failure handler
            null, // Options handler
            null, // Options Storage
            service('webauthn.logger')->nullOnInvalid(),
            service(EventDispatcherInterface::class)->nullOnInvalid(),
            [], // Secured Relying Party IDs
        ])
        ->tag('monolog.logger', ['channel' => 'security'])
    ;

    $container->services()->set(WebauthnEntryPoint::class)
        ->abstract()
        ->private()
        ->args([
            null, // Authentication failure handler
        ])
    ;

    $container->services()->set(IsUserPresentVoter::class)
        ->private()
        ->tag('security.voter')
    ;

    $container->services()->set(IsUserVerifiedVoter::class)
        ->private()
        ->tag('security.voter')
    ;

    $container->services()->set(DefaultSuccessHandler::class)
        ->private()
    ;

    $container->services()->set(DefaultFailureHandler::class)
        ->private()
    ;

    $container->services()->set(SessionStorage::class)
        ->private()
    ;

    $container->services()->set(DefaultCreationOptionsHandler::class)
        ->private()
    ;

    $container->services()->set(DefaultRequestOptionsHandler::class)
        ->private()
    ;
};
