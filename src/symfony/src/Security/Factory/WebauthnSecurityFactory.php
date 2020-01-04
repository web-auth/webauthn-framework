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

namespace Webauthn\Bundle\Security\Factory;

use Symfony\Bundle\SecurityBundle\DependencyInjection\Security\Factory\SecurityFactoryInterface;
use Symfony\Component\Config\Definition\Builder\ArrayNodeDefinition;
use Symfony\Component\Config\Definition\Builder\NodeDefinition;
use Symfony\Component\DependencyInjection\ChildDefinition;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Reference;
use Webauthn\Bundle\Security\Authentication\Provider\WebauthnProvider;
use Webauthn\Bundle\Security\EntryPoint\WebauthnEntryPoint;
use Webauthn\Bundle\Security\Handler\DefaultFailureHandler;
use Webauthn\Bundle\Security\Handler\DefaultRequestOptionsHandler;
use Webauthn\Bundle\Security\Handler\DefaultSuccessHandler;
use Webauthn\Bundle\Security\Storage\SessionStorage;

class WebauthnSecurityFactory implements SecurityFactoryInterface
{
    /**
     * @param string      $id
     * @param array       $config
     * @param string      $userProviderId
     * @param string|null $defaultEntryPointId
     */
    public function create(ContainerBuilder $container, $id, $config, $userProviderId, $defaultEntryPointId): array
    {
        $authProviderId = $this->createAuthProvider($container, $id, $config, $userProviderId);
        $entryPointId = $this->createEntryPoint($container, $id, $config);
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
        return 'webauthn';
    }

    /**
     * {@inheritdoc}
     *
     * webauthn:
     *   user_provider: null
     *   options_storage: SessionStorage::class
     *   http_message_factory: ----
     *   creation:
     *     enabled: true
     *     profile: default
     *     options_path: /attestation/options
     *     result_path: /attestation/result
     *     options_handler: DefaultCreationOptionsHandler::class
     *     success_handler: DefaultCreationSuccessHandler::class
     *     failure_handler: DefaultCreationFailureHandler::class
     *   request:
     *     enabled: true
     *     profile: default
     *     options_path: /assertion/options
     *     result_path: /assertion/result
     *     options_handler: DefaultRequestOptionsHandler::class
     *     success_handler: DefaultRequestSuccessHandler::class
     *     failure_handler: DefaultRequestFailureHandler::class
     */
    public function addConfiguration(NodeDefinition $node): void
    {
        /* @var ArrayNodeDefinition $node */
        $node
            ->children()
            ->scalarNode('profile')->isRequired()->end()
            ->scalarNode('options_path')->defaultValue('/login/options')->end()
            ->scalarNode('login_path')->defaultValue('/login')->end()
            ->scalarNode('user_provider')->defaultNull()->end()
            ->scalarNode('request_options_storage')->defaultValue(SessionStorage::class)->end()
            ->scalarNode('request_options_handler')->defaultValue(DefaultRequestOptionsHandler::class)->end()
            ->scalarNode('success_handler')->defaultValue(DefaultSuccessHandler::class)->end()
            ->scalarNode('failure_handler')->defaultValue(DefaultFailureHandler::class)->end()
            ->scalarNode('http_message_factory')->isRequired()->end()
            ->scalarNode('user_verification')->defaultNull()->end()
            ->arrayNode('extensions')
            ->treatFalseLike([])
            ->treatTrueLike([])
            ->treatNullLike([])
            ->useAttributeAsKey('name')
            ->scalarPrototype()->end()
            ->end()
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
        $listener->replaceArgument(0, new Reference($config['http_message_factory']));
        $listener->replaceArgument(12, $id);
        $listener->replaceArgument(13, $config);
        $listener->replaceArgument(14, new Reference($config['success_handler']));
        $listener->replaceArgument(15, new Reference($config['failure_handler']));
        $listener->replaceArgument(16, new Reference($config['request_options_handler']));
        $listener->replaceArgument(17, new Reference($config['request_options_storage']));

        $listenerId .= '.'.$id;
        $container->setDefinition($listenerId, $listener);

        return $listenerId;
    }

    private function createEntryPoint(ContainerBuilder $container, string $id, array $config): string
    {
        $entryPointId = 'webauthn.security.json.authentication.entrypoint.'.$id;
        $entryPoint = new ChildDefinition(WebauthnEntryPoint::class);
        $entryPoint->replaceArgument(0, new Reference($config['failure_handler']));

        $container->setDefinition($entryPointId, $entryPoint);

        return $entryPointId;
    }
}
