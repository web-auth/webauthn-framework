<?php

declare(strict_types=1);

use Psr\Cache\CacheItemPoolInterface;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\Serializer\SerializerInterface;
use Webauthn\Bundle\DependencyInjection\Factory\Security\WebauthnFactory;
use Webauthn\Bundle\Repository\PublicKeyCredentialSourceRepositoryInterface;
use Webauthn\Bundle\Repository\PublicKeyCredentialUserEntityRepositoryInterface;
use Webauthn\Bundle\Security\Authentication\WebauthnBadgeListener;
use Webauthn\Bundle\Security\Authorization\Voter\IsUserPresentVoter;
use Webauthn\Bundle\Security\Authorization\Voter\IsUserVerifiedVoter;
use Webauthn\Bundle\Security\Guesser\CurrentUserEntityGuesser;
use Webauthn\Bundle\Security\Guesser\RequestBodyUserEntityGuesser;
use Webauthn\Bundle\Security\Handler\DefaultCreationOptionsHandler;
use Webauthn\Bundle\Security\Handler\DefaultFailureHandler;
use Webauthn\Bundle\Security\Handler\DefaultRequestOptionsHandler;
use Webauthn\Bundle\Security\Handler\DefaultSuccessHandler;
use Webauthn\Bundle\Security\Http\Authenticator\WebauthnAuthenticator;
use Webauthn\Bundle\Security\Storage\CacheStorage;
use Webauthn\Bundle\Security\Storage\SessionStorage;
use Webauthn\Bundle\Security\WebauthnFirewallConfig;
use function Symfony\Component\DependencyInjection\Loader\Configurator\abstract_arg;
use function Symfony\Component\DependencyInjection\Loader\Configurator\service;

return static function (ContainerConfigurator $container): void {
    $service = $container->services()
        ->defaults()
        ->private()
        ->autoconfigure()
        ->autowire()
    ;
    $service->set(IsUserPresentVoter::class)->tag('security.voter');
    $service->set(IsUserVerifiedVoter::class)->tag('security.voter');
    $service->set(DefaultSuccessHandler::class);
    $service->set(DefaultFailureHandler::class);
    $service->set(SessionStorage::class)->args([service('request_stack')]);
    $service->set(CacheStorage::class)->args([service(CacheItemPoolInterface::class)]);
    $service->set(DefaultCreationOptionsHandler::class);
    $service->set(DefaultRequestOptionsHandler::class);
    $service
        ->set(WebauthnFactory::AUTHENTICATOR_DEFINITION_ID, WebauthnAuthenticator::class)
        ->abstract()
        ->args([
            abstract_arg('Firewall config'),
            abstract_arg('User provider'),
            abstract_arg('Success handler'),
            abstract_arg('Failure handler'),
            abstract_arg('Options Storage'),
            service(PublicKeyCredentialSourceRepositoryInterface::class),
            service(PublicKeyCredentialUserEntityRepositoryInterface::class),
            service(SerializerInterface::class),
            abstract_arg('Authenticator Assertion Response Validator'),
            abstract_arg('Authenticator Attestation Response Validator'),
        ]);
    $service
        ->set(WebauthnFactory::FIREWALL_CONFIG_DEFINITION_ID, WebauthnFirewallConfig::class)
        ->abstract()
        ->args([[], abstract_arg('Firewall name'), service('security.http_utils')]);

    $service->set(CurrentUserEntityGuesser::class);
    $service->set(RequestBodyUserEntityGuesser::class);
    $service->set(WebauthnBadgeListener::class)
        ->arg('$userProvider', service('security.user_providers'))
    ;
};
