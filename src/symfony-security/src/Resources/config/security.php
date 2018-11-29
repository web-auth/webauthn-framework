<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Webauthn\Security\Bundle\Security\Authentication\Provider\WebauthnProvider;
use Webauthn\Security\Bundle\Security\EntryPoint\UsernameEntryPoint;
use Webauthn\Security\Bundle\Security\Firewall\WebauthnListener;
use function Symfony\Component\DependencyInjection\Loader\Configurator\ref;

return function (ContainerConfigurator $container) {
    $container = $container->services()->defaults()
        ->private()
        ->autoconfigure()
        ->autowire();

    $container->set(WebauthnProvider::class)
        ->abstract(true)
        ->arg(0, ref(\Symfony\Component\Security\Core\User\UserCheckerInterface::class))
    ;

    $container->set(WebauthnListener::class)
        ->abstract(true)
        ->arg(0, ref(\Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface::class))
        ->arg(1, ref(\Symfony\Component\Security\Core\Authentication\AuthenticationManagerInterface::class))
        ->arg(2, ref(\Symfony\Component\Security\Http\HttpUtils::class))
        ->arg(3, '')
        ->arg(4, [])
        ->arg(5, ref(\Symfony\Component\PropertyAccess\PropertyAccessorInterface::class)->nullOnInvalid())
    ;

    $container->set(UsernameEntryPoint::class)
        ->abstract(true)
        ->arg(0, ref(\Symfony\Component\HttpKernel\KernelInterface::class))
    ;
};
