<?php

declare(strict_types=1);

use function Symfony\Component\DependencyInjection\Loader\Configurator\abstract_arg;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use function Symfony\Component\DependencyInjection\Loader\Configurator\service;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Serializer\SerializerInterface;
use Symfony\Component\Validator\Validator\ValidatorInterface;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\Bundle\DependencyInjection\Factory\Security\WebauthnFactory;
use Webauthn\Bundle\Repository\PublicKeyCredentialUserEntityRepository;
use Webauthn\Bundle\Security\Authorization\Voter\IsUserPresentVoter;
use Webauthn\Bundle\Security\Authorization\Voter\IsUserVerifiedVoter;
use Webauthn\Bundle\Security\Guesser\CurrentUserEntityGuesser;
use Webauthn\Bundle\Security\Guesser\RequestBodyUserEntityGuesser;
use Webauthn\Bundle\Security\Handler\DefaultCreationOptionsHandler;
use Webauthn\Bundle\Security\Handler\DefaultFailureHandler;
use Webauthn\Bundle\Security\Handler\DefaultRequestOptionsHandler;
use Webauthn\Bundle\Security\Handler\DefaultSuccessHandler;
use Webauthn\Bundle\Security\Http\Authenticator\WebauthnAuthenticator;
use Webauthn\Bundle\Security\Storage\SessionStorage;
use Webauthn\Bundle\Security\WebauthnFirewallConfig;
use Webauthn\PublicKeyCredentialLoader;
use Webauthn\PublicKeyCredentialSourceRepository;

return static function (ContainerConfigurator $container): void {
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
            service(PublicKeyCredentialSourceRepository::class),
            service(PublicKeyCredentialUserEntityRepository::class),
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
