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
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\Bundle\Controller\AttestationResponseControllerFactory;
use Webauthn\Bundle\Repository\PublicKeyCredentialUserEntityRepository;
use Webauthn\Bundle\Security\Authentication\Provider\WebauthnProvider;
use Webauthn\Bundle\Security\EntryPoint\WebauthnEntryPoint;
use Webauthn\Bundle\Security\Firewall\WebauthnListener;
use Webauthn\Bundle\Security\Handler\DefaultAuthenticationFailureHandler;
use Webauthn\Bundle\Security\Handler\DefaultAuthenticationSuccessHandler;
use Webauthn\Bundle\Security\Handler\DefaultCreationFailureHandler;
use Webauthn\Bundle\Security\Handler\DefaultRequestOptionsHandler;
use Webauthn\Bundle\Security\Storage\SessionStorage;
use Webauthn\Bundle\Security\Voter\IsUserPresentVoter;
use Webauthn\Bundle\Security\Voter\IsUserVerifiedVoter;
use Webauthn\Bundle\Service\PublicKeyCredentialRequestOptionsFactory;
use Webauthn\PublicKeyCredentialLoader;
use Webauthn\PublicKeyCredentialSourceRepository;

return function (ContainerConfigurator $container) {
    $container = $container->services()->defaults()
        ->private()
        ->autoconfigure()
        ->autowire()
    ;

    $container->set(WebauthnProvider::class)
        ->arg(0, ref(UserCheckerInterface::class))
    ;

    $container->set('security.authentication.listener.webauthn.json')
        ->class(WebauthnListener::class)
        ->abstract()
        ->args([
            '', // HTTP Message Factory
            ref(SerializerInterface::class),
            ref(ValidatorInterface::class),
            ref(PublicKeyCredentialRequestOptionsFactory::class),
            ref(PublicKeyCredentialSourceRepository::class),
            ref(PublicKeyCredentialUserEntityRepository::class),
            ref(PublicKeyCredentialLoader::class),
            ref(AuthenticatorAssertionResponseValidator::class),
            ref(AuthenticatorAttestationResponseValidator::class),
            ref(TokenStorageInterface::class),
            ref(AuthenticationManagerInterface::class),
            ref(SessionAuthenticationStrategyInterface::class),
            ref(HttpUtils::class),
            null, // Fake user provider
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

    $container->set(WebauthnEntryPoint::class)
        ->abstract()
        ->args([
            null, // Authentication failure handler
        ])
    ;

    $container->set(IsUserPresentVoter::class)
        ->tag('security.voter')
    ;

    $container->set(IsUserVerifiedVoter::class)
        ->tag('security.voter')
    ;

    $container->set(DefaultAuthenticationSuccessHandler::class);

    $container->set(DefaultAuthenticationFailureHandler::class);

    $container->set(DefaultCreationFailureHandler::class);

    $container->set(SessionStorage::class);

    $container->set(DefaultRequestOptionsHandler::class);

    $container->set(AttestationResponseControllerFactory::class);
};
