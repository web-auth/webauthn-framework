<?php

declare(strict_types=1);

use Psr\Log\LoggerInterface;
use function Symfony\Component\DependencyInjection\Loader\Configurator\abstract_arg;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use function Symfony\Component\DependencyInjection\Loader\Configurator\service;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\User\UserCheckerInterface;
use Symfony\Component\Security\Http\HttpUtils;
use Symfony\Component\Security\Http\Session\SessionAuthenticationStrategyInterface;
use Symfony\Component\Serializer\SerializerInterface;
use Symfony\Component\Validator\Validator\ValidatorInterface;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\Bundle\DependencyInjection\Factory\Security\WebauthnFactory;
use Webauthn\Bundle\Repository\PublicKeyCredentialUserEntityRepository;
//use Symfony\Component\Security\Core\Authentication\AuthenticationManagerInterface;
use Webauthn\Bundle\Security\Authorization\Voter\IsUserPresentVoter;
use Webauthn\Bundle\Security\Authorization\Voter\IsUserVerifiedVoter;
use Webauthn\Bundle\Security\Guesser\CurrentUserEntityGuesser;
use Webauthn\Bundle\Security\Guesser\RequestBodyUserEntityGuesser;
use Webauthn\Bundle\Security\Handler\DefaultCreationOptionsHandler;
use Webauthn\Bundle\Security\Handler\DefaultFailureHandler;
use Webauthn\Bundle\Security\Handler\DefaultRequestOptionsHandler;
use Webauthn\Bundle\Security\Handler\DefaultSuccessHandler;
use Webauthn\Bundle\Security\Http\Authenticator\WebauthnAuthenticator;
//use Webauthn\Bundle\Security\Authentication\Provider\WebauthnProvider;
//use Webauthn\Bundle\Security\EntryPoint\WebauthnEntryPoint;
//use Webauthn\Bundle\Security\Firewall\CreationListener;
//use Webauthn\Bundle\Security\Firewall\RequestListener;
//use Webauthn\Bundle\Security\Firewall\WebauthnListener;
use Webauthn\Bundle\Security\Listener\RequestResultListener;
use Webauthn\Bundle\Security\Storage\SessionStorage;
use Webauthn\Bundle\Security\WebauthnFirewallConfig;
use Webauthn\Bundle\Security\WebauthnFirewallContext;
//use Webauthn\Bundle\Service\PublicKeyCredentialCreationOptionsFactory;
use Webauthn\Bundle\Service\PublicKeyCredentialRequestOptionsFactory;
use Webauthn\PublicKeyCredentialLoader;
use Webauthn\PublicKeyCredentialSourceRepository;

return static function (ContainerConfigurator $container): void {
    /*$container->services()
        ->set(WebauthnProvider::class)
        ->private()
        ->arg(0, service(UserCheckerInterface::class))
    ;*/

    /*$container->services()
        ->set('security.authentication.listener.webauthn')
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
        ->tag('monolog.logger', [
            'channel' => 'security',
        ])
    ;*/

    $container->services()
        ->set(WebauthnFactory::REQUEST_RESULT_LISTENER_DEFINITION_ID, RequestResultListener::class)
        ->abstract()
        ->args([
            abstract_arg('HTTP Message Factory'),
            abstract_arg('Firewall config'),
            abstract_arg('Authentication success handler'),
            abstract_arg('Authentication failure handler'),
            abstract_arg('Options Storage'),
            abstract_arg('Secured Relying Party IDs'),
            service(PublicKeyCredentialUserEntityRepository::class),
            service(PublicKeyCredentialLoader::class),
            service(AuthenticatorAssertionResponseValidator::class),
            service(TokenStorageInterface::class),
            service(SessionAuthenticationStrategyInterface::class),
            service(EventDispatcherInterface::class)->nullOnInvalid(),
        ])
        ->tag('monolog.logger', [
            'channel' => 'security',
        ])
    ;

    /*$container->services()
        ->set('security.authentication.listener.webauthn.creation')
        ->class(CreationListener::class)
        ->abstract()
        ->private()
        ->args([
            '', // HTTP Message Factory
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
            service('webauthn.logger')
                ->nullOnInvalid(),
            service(EventDispatcherInterface::class)->nullOnInvalid(),
            [], // Secured Relying Party IDs
        ])
        ->tag('monolog.logger', [
            'channel' => 'security',
        ])
    ;*/

    /*$container->services()
        ->set(WebauthnEntryPoint::class)
        ->abstract()
        ->private()
        ->args([
            null, // Authentication failure handler
        ])
    ;*/

    $container->services()
        ->set(IsUserPresentVoter::class)
        ->private()
        ->tag('security.voter')
    ;

    $container->services()
        ->set(IsUserVerifiedVoter::class)
        ->private()
        ->tag('security.voter')
    ;

    $container->services()
        ->set(DefaultSuccessHandler::class)
        ->private()
    ;

    $container->services()
        ->set(DefaultFailureHandler::class)
        ->private()
    ;

    $container->services()
        ->set(SessionStorage::class)
        ->private()
    ;

    $container->services()
        ->set(DefaultCreationOptionsHandler::class)
        ->private()
    ;

    $container->services()
        ->set(DefaultRequestOptionsHandler::class)
        ->private()
    ;

    $container->services()
        ->set(WebauthnFactory::AUTHENTICATOR_DEFINITION_ID, WebauthnAuthenticator::class)
        ->abstract()
        ->args([
            abstract_arg('Firewall config'),
            abstract_arg('User provider'),
            abstract_arg('Success handler'),
            abstract_arg('Failure handler'),
            abstract_arg('Http Message Factory'),
            abstract_arg('Options Storage'),
            abstract_arg('Secured Relying Party IDs'),
            service(PublicKeyCredentialLoader::class),
            service(AuthenticatorAssertionResponseValidator::class),
            service(AuthenticatorAttestationResponseValidator::class),
            service('webauthn.logger')
                ->nullOnInvalid(),
        ])
    ;

    $container->services()
        ->set(WebauthnFactory::FIREWALL_CONFIG_DEFINITION_ID, WebauthnFirewallConfig::class)
        ->abstract()
        ->args([
            [], // Firewall settings
            abstract_arg('Firewall name'),
            service('security.http_utils'),
        ])
    ;

    $container->services()
        ->set(WebauthnFactory::FIREWALL_CONTEXT_DEFINITION_ID, WebauthnFirewallContext::class)
        ->abstract()
        ->public()
        ->args([abstract_arg('Firewall configs')])
    ;

    $container->services()
        ->set(CurrentUserEntityGuesser::class)
        ->args([service(TokenStorageInterface::class), service(PublicKeyCredentialUserEntityRepository::class)])
    ;
    $container->services()
        ->set(RequestBodyUserEntityGuesser::class)
        ->args([
            service(SerializerInterface::class),
            service(ValidatorInterface::class),
            service(PublicKeyCredentialUserEntityRepository::class),
        ])
    ;
};
