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

namespace Webauthn\JsonSecurityBundle\Security\Factory;

use Symfony\Bundle\SecurityBundle\DependencyInjection\Security\Factory\SecurityFactoryInterface;
use Symfony\Component\Config\Definition\Builder\ArrayNodeDefinition;
use Symfony\Component\Config\Definition\Builder\NodeDefinition;
use Symfony\Component\DependencyInjection\ChildDefinition;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Reference;
use Webauthn\JsonSecurityBundle\Security\Authentication\Provider\WebauthnProvider;
use Webauthn\JsonSecurityBundle\Security\EntryPoint\WebauthnEntryPoint;
use Webauthn\JsonSecurityBundle\Security\Handler\DefaultFailureHandler;
use Webauthn\JsonSecurityBundle\Security\Handler\DefaultSuccessHandler;

class WebauthnSecurityFactory implements SecurityFactoryInterface
{
    /**
     * @param ContainerBuilder $container
     * @param string           $id
     * @param array            $config
     * @param string           $userProviderId
     * @param string           $defaultEntryPointId
     *
     * @return array
     */
    public function create(ContainerBuilder $container, $id, $config, $userProviderId, $defaultEntryPointId): array
    {
        $authProviderId = $this->createAuthProvider($container, $id, $config, $userProviderId);
        $entryPointId = $this->createEntryPoint($container, $id);
        $listenerId = $this->createListener($container, $id, $config);

        return [$authProviderId, $listenerId, $entryPointId];
    }

    /**
     * {@inheritdoc}
     */
    public function getPosition(): string
    {
        return 'form';
    }

    /**
     * {@inheritdoc}
     */
    public function getKey(): string
    {
        return 'webauthn_json';
    }

    /**
     * {@inheritdoc}
     */
    public function addConfiguration(NodeDefinition $node): void
    {
        /* @var ArrayNodeDefinition $node */
        $node
            ->addDefaultsIfNotSet()
            ->children()
                ->scalarNode('profile')->isRequired()->end()
                ->scalarNode('options_path')->defaultValue('/login/options')->end()
                ->scalarNode('login_path')->defaultValue('/login')->end()
                ->scalarNode('session_parameter')->defaultValue('WEBAUTHN_PUBLIC_KEY_REQUEST_OPTIONS')->end()
                ->scalarNode('user_provider')->defaultNull()->end()
                ->scalarNode('success_handler')->defaultValue(DefaultSuccessHandler::class)->end()
                ->scalarNode('failure_handler')->defaultValue(DefaultFailureHandler::class)->end()
            ->end()
        ;
    }

    private function createAuthProvider(ContainerBuilder $container, string $id, array $config, string $userProviderId): string
    {
        $providerId = 'security.authentication.provider.webauthn.json.'.$id;
        $container
            ->setDefinition($providerId, new ChildDefinition(WebauthnProvider::class))
            ->setArgument(1, new Reference($userProviderId))
        ;

        return $providerId;
    }

    private function createListener(ContainerBuilder $container, string $id, array $config): string
    {
        $listenerId = 'security.authentication.listener.webauthn.json';
        $listener = new ChildDefinition($listenerId);
        $listener->replaceArgument(13, $id);
        $listener->replaceArgument(14, $config);
        $listener->replaceArgument(15, new Reference($config['success_handler']));
        $listener->replaceArgument(16, new Reference($config['failure_handler']));

        $listenerId .= '.'.$id;
        $container->setDefinition($listenerId, $listener);

        return $listenerId;
    }

    private function createEntryPoint(ContainerBuilder $container, string $id): string
    {
        $entryPointId = 'webauthn.security.json.authentication.entrypoint.'.$id;
        $container->setDefinition($entryPointId, new ChildDefinition(WebauthnEntryPoint::class));

        return $entryPointId;
    }
}
