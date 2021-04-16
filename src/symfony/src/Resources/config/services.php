<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2020 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
 use function Symfony\Component\DependencyInjection\Loader\Configurator\service;
use Symfony\Contracts\EventDispatcher\EventDispatcherInterface;
use Webauthn\AttestationStatement\AttestationObjectLoader;
/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2020 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AttestationStatement\NoneAttestationStatementSupport;
use Webauthn\AuthenticationExtensions\ExtensionOutputCheckerHandler;
use Webauthn\AuthenticatorAssertionResponseValidator as BaseAuthenticatorAssertionResponseValidator;
use Webauthn\AuthenticatorAttestationResponseValidator as BaseAuthenticatorAttestationResponseValidator;
use Webauthn\Bundle\Controller\DummyControllerFactory;
use Webauthn\Bundle\Repository\DummyPublicKeyCredentialSourceRepository;
use Webauthn\Bundle\Repository\DummyPublicKeyCredentialUserEntityRepository;
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
    $container = $container->services()->defaults()
        ->private()
        ->autoconfigure()
        ->autowire()
    ;

    $container->set(BaseAuthenticatorAttestationResponseValidator::class)
        ->class(AuthenticatorAttestationResponseValidator::class)
        ->args([
            service(AttestationStatementSupportManager::class),
            service(PublicKeyCredentialSourceRepository::class),
            service(TokenBindingHandler::class),
            service(ExtensionOutputCheckerHandler::class),
            service(EventDispatcherInterface::class),
        ])
        ->public()
    ;
    $container->set(BaseAuthenticatorAssertionResponseValidator::class)
        ->class(AuthenticatorAssertionResponseValidator::class)
        ->args([
            service(PublicKeyCredentialSourceRepository::class),
            service(TokenBindingHandler::class),
            service(ExtensionOutputCheckerHandler::class),
            service('webauthn.cose.algorithm.manager'),
            service(EventDispatcherInterface::class),
        ])
        ->public()
    ;
    $container->set(PublicKeyCredentialLoader::class)
        ->args([
            service(AttestationObjectLoader::class),
        ])
        ->public()
    ;
    $container->set(PublicKeyCredentialCreationOptionsFactory::class)
        ->args([
            '%webauthn.creation_profiles%',
            service(EventDispatcherInterface::class),
        ])
        ->public()
    ;
    $container->set(PublicKeyCredentialRequestOptionsFactory::class)
        ->args([
            '%webauthn.request_profiles%',
            service(EventDispatcherInterface::class),
        ])
        ->public()
    ;

    $container->set(ExtensionOutputCheckerHandler::class);
    $container->set(AttestationObjectLoader::class)
        ->args([
            service(AttestationStatementSupportManager::class),
        ])
    ;
    $container->set(AttestationStatementSupportManager::class);
    $container->set(NoneAttestationStatementSupport::class);

    $container->set(IgnoreTokenBindingHandler::class);
    $container->set(TokenBindingNotSupportedHandler::class);
    $container->set(SecTokenBindingHandler::class);

    $container->set(ThrowExceptionIfInvalid::class);

    $container->set(Loader::class)
        ->tag('routing.loader')
    ;

    $container->set(DummyControllerFactory::class);
    $container->set(DummyPublicKeyCredentialSourceRepository::class);
    $container->set(DummyPublicKeyCredentialUserEntityRepository::class);
};
