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
use function Symfony\Component\DependencyInjection\Loader\Configurator\ref;
use Symfony\Contracts\EventDispatcher\EventDispatcherInterface;
use Webauthn\AttestationStatement;
use Webauthn\AttestationStatement\AttestationObjectLoader;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
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
use Webauthn\Counter;
use Webauthn\MetadataService\MetadataStatementRepository;
use Webauthn\PublicKeyCredentialLoader;
use Webauthn\PublicKeyCredentialSourceRepository;
use Webauthn\TokenBinding;
use Webauthn\TokenBinding\TokenBindingHandler;

return static function (ContainerConfigurator $container): void {
    $container = $container->services()->defaults()
        ->private()
        ->autoconfigure()
        ->autowire();

    $container->set(BaseAuthenticatorAttestationResponseValidator::class)
        ->class(AuthenticatorAttestationResponseValidator::class)
        ->args([
            ref(AttestationStatementSupportManager::class),
            ref(PublicKeyCredentialSourceRepository::class),
            ref(TokenBindingHandler::class),
            ref(ExtensionOutputCheckerHandler::class),
            ref(EventDispatcherInterface::class),
            ref(MetadataStatementRepository::class)->nullOnInvalid(),
            ref('webauthn.logger')->nullOnInvalid(),
        ])
        ->public();
    $container->set(BaseAuthenticatorAssertionResponseValidator::class)
        ->class(AuthenticatorAssertionResponseValidator::class)
        ->args([
            ref(PublicKeyCredentialSourceRepository::class),
            ref(TokenBinding\TokenBindingHandler::class),
            ref(ExtensionOutputCheckerHandler::class),
            ref('webauthn.cose.algorithm.manager'),
            ref(EventDispatcherInterface::class),
            ref(Counter\CounterChecker::class)->nullOnInvalid(),
            ref('webauthn.logger')->nullOnInvalid(),
        ])
        ->public();
    $container->set(PublicKeyCredentialLoader::class)
        ->args([
            ref(AttestationObjectLoader::class),
            ref('webauthn.logger')->nullOnInvalid(),
        ])
        ->public();
    $container->set(PublicKeyCredentialCreationOptionsFactory::class)
        ->args([
            '%webauthn.creation_profiles%',
            ref(EventDispatcherInterface::class),
        ])
        ->public();
    $container->set(PublicKeyCredentialRequestOptionsFactory::class)
        ->args([
            '%webauthn.request_profiles%',
            ref(EventDispatcherInterface::class),
        ])
        ->public();

    $container->set(ExtensionOutputCheckerHandler::class);
    $container->set(AttestationStatement\AttestationObjectLoader::class)
        ->args([
            ref(AttestationStatementSupportManager::class),
            null,
            ref('webauthn.logger')->nullOnInvalid(),
        ]);
    $container->set(AttestationStatement\AttestationStatementSupportManager::class);
    $container->set(AttestationStatement\NoneAttestationStatementSupport::class);

    $container->set(TokenBinding\IgnoreTokenBindingHandler::class);
    $container->set(TokenBinding\TokenBindingNotSupportedHandler::class);
    $container->set(TokenBinding\SecTokenBindingHandler::class);

    $container->set(Counter\ThrowExceptionIfInvalid::class);

    $container->set(Loader::class)
        ->tag('routing.loader');

    $container->set(DummyControllerFactory::class);
    $container->set(DummyPublicKeyCredentialSourceRepository::class);
    $container->set(DummyPublicKeyCredentialUserEntityRepository::class);
};
