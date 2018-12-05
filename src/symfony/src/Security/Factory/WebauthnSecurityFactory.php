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
use Webauthn\Bundle\Security\Authentication\Provider\MetaWebauthnProvider;
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

    public function addConfiguration(NodeDefinition $node)
    {
        /* @var ArrayNodeDefinition $node */
        $node
            ->addDefaultsIfNotSet()
            ->children()
                ->scalarNode('login_path')->defaultValue('/login')->end()
                ->scalarNode('login_check_path')->defaultValue('/login_check')->end()
                ->scalarNode('assertion_path')->defaultValue('/login_assertion')->end()
                ->scalarNode('assertion_check_path')->defaultValue('/login_check_assertion')->end()
                ->booleanNode('use_forward')->defaultFalse()->end()
                ->booleanNode('require_previous_session')->defaultFalse()->end()
                ->scalarNode('user_provider')->end()
                ->booleanNode('remember_me')->defaultTrue()->end()
                ->scalarNode('success_handler')->end()
                ->scalarNode('failure_handler')->end()
                ->scalarNode('username_parameter')->defaultValue('_username')->end()
                ->scalarNode('assertion_parameter')->defaultValue('_assertion')->end()
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

    private function createAuthProvider(ContainerBuilder $container, string $id, array $config, string $userProviderId): string
    {
        $providerId = 'security.authentication.provider.webauthn.'.$id;
        $container
            ->setDefinition($providerId, new ChildDefinition(MetaWebauthnProvider::class))
            ->setArgument(2, new Reference($userProviderId))
            ->setArgument(3, $id)
        ;

        return $providerId;
    }

    private function createListener(ContainerBuilder $container, string $id, array $config, string $userProviderId): string
    {
        $listenerId = 'security.authentication.listener.webauthn';
        $listener = new ChildDefinition($listenerId);
        $listener->replaceArgument(6, $id);
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
