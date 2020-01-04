<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2019 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

use Psr\Log\LoggerInterface;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use function Symfony\Component\DependencyInjection\Loader\Configurator\ref;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\Security\Core\Authentication\AuthenticationManagerInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\User\UserCheckerInterface;
use Symfony\Component\Security\Http\HttpUtils;
use Symfony\Component\Security\Http\Session\SessionAuthenticationStrategyInterface;
use Symfony\Component\Serializer\SerializerInterface;
use Symfony\Component\Validator\Validator\ValidatorInterface;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\Bundle\Repository\PublicKeyCredentialUserEntityRepository;
use Webauthn\Bundle\Security\Authentication\Provider\WebauthnProvider;
use Webauthn\Bundle\Security\EntryPoint\WebauthnEntryPoint;
use Webauthn\Bundle\Security\Firewall\WebauthnListener;
use Webauthn\Bundle\Security\Handler\DefaultCreationOptionsHandler;
use Webauthn\Bundle\Security\Handler\DefaultFailureHandler;
use Webauthn\Bundle\Security\Handler\DefaultRequestOptionsHandler;
use Webauthn\Bundle\Security\Handler\DefaultSuccessHandler;
use Webauthn\Bundle\Security\Storage\SessionStorage;
use Webauthn\Bundle\Security\Voter\IsUserPresentVoter;
use Webauthn\Bundle\Security\Voter\IsUserVerifiedVoter;
use Webauthn\Bundle\Service\PublicKeyCredentialRequestOptionsFactory;
use Webauthn\PublicKeyCredentialLoader;
use Webauthn\PublicKeyCredentialSourceRepository;

return static function (ContainerConfigurator $container): void {
    $container->services()->set(WebauthnProvider::class)
        ->private()
        ->arg(0, ref(UserCheckerInterface::class))
    ;

    $container->services()->set('security.authentication.listener.webauthn.json')
        ->class(WebauthnListener::class)
        ->abstract()
        ->private()
        ->args([
            '', // HTTP Message Factory
            ref(SerializerInterface::class),
            ref(ValidatorInterface::class),
            ref(PublicKeyCredentialRequestOptionsFactory::class),
            ref(PublicKeyCredentialSourceRepository::class),
            ref(PublicKeyCredentialUserEntityRepository::class),
            ref(PublicKeyCredentialLoader::class),
            ref(AuthenticatorAssertionResponseValidator::class),
            ref(TokenStorageInterface::class),
            ref(AuthenticationManagerInterface::class),
            ref(SessionAuthenticationStrategyInterface::class),
            ref(HttpUtils::class),
            '', // Provider key
            [], // Options
            null, // Authentication success handler
            null, // Authentication failure handler
            null, // Request Options handler
            null, // Request Options Storage
            ref(LoggerInterface::class)->nullOnInvalid(),
            ref(EventDispatcherInterface::class)->nullOnInvalid(),
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
