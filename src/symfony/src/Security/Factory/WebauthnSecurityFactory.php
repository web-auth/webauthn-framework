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

namespace Webauthn\Bundle\Security\Factory;

use Symfony\Bundle\SecurityBundle\DependencyInjection\Security\Factory\SecurityFactoryInterface;
use Symfony\Component\Config\Definition\Builder\ArrayNodeDefinition;
use Symfony\Component\Config\Definition\Builder\NodeDefinition;
use Symfony\Component\DependencyInjection\ChildDefinition;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Reference;
use Webauthn\Bundle\Security\Authentication\Provider\WebauthnProvider;
use Webauthn\Bundle\Security\EntryPoint\WebauthnEntryPoint;
use Webauthn\PublicKeyCredentialRequestOptions;

class WebauthnSecurityFactory implements SecurityFactoryInterface
{
    public function create(ContainerBuilder $container, $id, $config, $userProviderId, $defaultEntryPointId)
    {
        $authProviderId = $this->createAuthProvider($container, $id, $config, $userProviderId);
        $entryPointId = $this->createEntryPoint($container, $id, $config);
        $listenerId = $this->createListener($container, $id, $config, $userProviderId);
        if ($this->isRememberMeAware($config)) {
            $container
                ->getDefinition($listenerId)
                ->addTag('security.remember_me_aware', ['id' => $id, 'user_provider' => $userProviderId])
            ;
        }

        return [$authProviderId, $listenerId, $entryPointId];
    }

    public function getPosition()
    {
        return 'form';
    }

    public function getKey()
    {
        return 'webauthn';
    }

    private $defaultSuccessHandlerOptions = [
        'always_use_default_target_path' => false,
        'default_target_path' => '/',
        'login_path' => '/login',
        'target_path_parameter' => '_target_path',
        'use_referer' => false,
    ];

    private $defaultFailureHandlerOptions = [
        'failure_path' => null,
        'failure_forward' => false,
        'login_path' => '/login',
        'failure_path_parameter' => '_failure_path',
    ];

    public function addConfiguration(NodeDefinition $node)
    {
        /* @var ArrayNodeDefinition $node */
        $node
            ->addDefaultsIfNotSet()
            ->children()
                ->scalarNode('login_path')->defaultValue('/login')->end()
                ->scalarNode('assertion_path')->defaultValue('/login_assertion')->end()
                ->scalarNode('check_path')->defaultValue('/login_check')->end()
                ->booleanNode('use_forward')->defaultFalse()->end()
                ->booleanNode('require_previous_session')->defaultFalse()->end()
                ->scalarNode('user_provider')->end()
                ->booleanNode('remember_me')->defaultTrue()->end()
                ->scalarNode('success_handler')->end()
                ->scalarNode('failure_handler')->end()
                ->scalarNode('username_parameter')->defaultValue('_username')->end()
                ->scalarNode('csrf_parameter')->defaultValue('_csrf_token')->end()
                ->scalarNode('csrf_token_id')->defaultValue('authenticate')->end()
                ->arrayNode('relaying_party')
                    ->addDefaultsIfNotSet()
                    ->children()
                        ->scalarNode('id')->defaultNull()->end()
                        ->scalarNode('name')->defaultValue('Webauthn Security')->end()
                        ->scalarNode('icon')->defaultNull()->end()
                    ->end()
                ->end()
                ->integerNode('timeout')->defaultValue(60000)->min(0)->end()
                ->integerNode('challenge_length')->defaultValue(32)->min(16)->end()
                ->scalarNode('user_verification')->defaultValue(PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_PREFERRED)->end()
            ->end()
        ;
    }

    private function isRememberMeAware(array $config): bool
    {
        return $config['remember_me'];
    }

    private function createAuthenticationSuccessHandler(ContainerBuilder $container, string $id, array $config)
    {
        $successHandlerId = 'security.authentication.success_handler.'.$id.'.'.str_replace('-', '_', $this->getKey());
        $options = array_intersect_key($config, $this->defaultSuccessHandlerOptions);

        if (isset($config['success_handler'])) {
            $successHandler = $container->setDefinition($successHandlerId, new ChildDefinition('security.authentication.custom_success_handler'));
            $successHandler->replaceArgument(0, new Reference($config['success_handler']));
            $successHandler->replaceArgument(1, $options);
            $successHandler->replaceArgument(2, $id);
        } else {
            $successHandler = $container->setDefinition($successHandlerId, new ChildDefinition('security.authentication.success_handler'));
            $successHandler->addMethodCall('setOptions', [$options]);
            $successHandler->addMethodCall('setProviderKey', [$id]);
        }

        return $successHandlerId;
    }

    private function createAuthenticationFailureHandler(ContainerBuilder $container, string $id, array $config)
    {
        $id = 'security.authentication.failure_handler.'.$id.'.'.str_replace('-', '_', $this->getKey());
        $options = array_intersect_key($config, $this->defaultFailureHandlerOptions);

        if (isset($config['failure_handler'])) {
            $failureHandler = $container->setDefinition($id, new ChildDefinition('security.authentication.custom_failure_handler'));
            $failureHandler->replaceArgument(0, new Reference($config['failure_handler']));
            $failureHandler->replaceArgument(1, $options);
        } else {
            $failureHandler = $container->setDefinition($id, new ChildDefinition('security.authentication.failure_handler'));
            $failureHandler->addMethodCall('setOptions', [$options]);
        }

        return $id;
    }

    private function createAuthProvider(ContainerBuilder $container, string $id, array $config, string $userProviderId): string
    {
        $providerId = 'security.authentication.provider.webauthn.'.$id;
        $container
            ->setDefinition($providerId, new ChildDefinition(WebauthnProvider::class))
            ->setArgument(1, new Reference($userProviderId))
            ->setArgument(2, $id)
        ;

        return $providerId;
    }

    private function createListener(ContainerBuilder $container, string $id, array $config, string $userProviderId): string
    {
        $listenerId = 'security.authentication.listener.webauthn';
        $listener = new ChildDefinition($listenerId);
        $listener->replaceArgument(4, $id);
        $listener->replaceArgument(5, new Reference($this->createAuthenticationSuccessHandler($container, $id, $config)));
        $listener->replaceArgument(6, new Reference($this->createAuthenticationFailureHandler($container, $id, $config)));
        $listener->replaceArgument(7, $config);

        $listenerId .= '.'.$id;
        $container->setDefinition($listenerId, $listener);

        $container
            ->getDefinition($listenerId)
            ->addArgument(isset($config['csrf_token_generator']) ? new Reference($config['csrf_token_generator']) : null)
        ;

        return $listenerId;
    }

    private function createEntryPoint(ContainerBuilder $container, string $id, array $config): string
    {
        $entryPointId = 'webauthn.security.authentication.entry_point.'.$id;
        $container
            ->setDefinition($entryPointId, new ChildDefinition(WebauthnEntryPoint::class))
            ->addArgument(new Reference('security.http_utils'))
            ->addArgument($config['login_path'])
            ->addArgument($config['use_forward'])
        ;

        return $entryPointId;
    }
}
