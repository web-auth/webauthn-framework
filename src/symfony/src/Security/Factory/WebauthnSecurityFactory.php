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

namespace Webauthn\Bundle\Security\Factory;

use JetBrains\PhpStorm\Pure;
use function Safe\sprintf;
use Symfony\Bundle\SecurityBundle\DependencyInjection\Security\Factory\SecurityFactoryInterface;
use Symfony\Component\Config\Definition\Builder\ArrayNodeDefinition;
use Symfony\Component\Config\Definition\Builder\NodeDefinition;
use Symfony\Component\DependencyInjection\ChildDefinition;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Reference;
use Webauthn\Bundle\Controller\DummyController;
use Webauthn\Bundle\Controller\DummyControllerFactory;
use Webauthn\Bundle\DependencyInjection\Compiler\DynamicRouteCompilerPass;
use Webauthn\Bundle\Security\Authentication\Provider\WebauthnProvider;
use Webauthn\Bundle\Security\EntryPoint\WebauthnEntryPoint;
use Webauthn\Bundle\Security\Handler\DefaultCreationOptionsHandler;
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
     * @param string|null $defaultEntryPoint
     *
     * @return string[]
     */
    public function create(ContainerBuilder $container, $id, $config, $userProviderId, $defaultEntryPoint): array
    {
        $authProviderId = $this->createAuthProvider($container, $id, $userProviderId);
        $entryPointId = $this->createEntryPoint($container, $id, $config);
        $listenerId = $this->createListener($container, $id, $config);

        return [$authProviderId, $listenerId, $entryPointId];
    }

    /**
     * {@inheritdoc}
     */
    #[Pure]
    public function getPosition(): string
    {
        return 'form';
    }

    /**
     * {@inheritdoc}
     */
    #[Pure]
    public function getKey(): string
    {
        return 'webauthn';
    }

    /**
     * {@inheritdoc}
     */
    public function addConfiguration(NodeDefinition $node): void
    {
        /* @var ArrayNodeDefinition $node */
        $node
            ->children()
            ->scalarNode('user_provider')->defaultNull()->end()
            ->scalarNode('options_storage')->defaultValue(SessionStorage::class)->end()
            ->scalarNode('success_handler')->defaultValue(DefaultSuccessHandler::class)->end()
            ->scalarNode('failure_handler')->defaultValue(DefaultFailureHandler::class)->end()
            ->arrayNode('secured_rp_ids')
            ->treatFalseLike([])
            ->treatTrueLike([])
            ->treatNullLike([])
            ->useAttributeAsKey('name')
            ->scalarPrototype()->end()
            ->end()
            ->arrayNode('authentication')
            ->canBeDisabled()
            ->children()
            ->scalarNode('profile')->defaultValue('default')->end()
            ->arrayNode('routes')
            ->addDefaultsIfNotSet()
            ->children()
            ->scalarNode('host')->defaultNull()->end()
            ->scalarNode('options_path')->defaultValue('/login/options')->end()
            ->scalarNode('result_path')->defaultValue('/login')->end()
            ->end()
            ->end()
            ->scalarNode('options_handler')->defaultValue(DefaultRequestOptionsHandler::class)->end()
            ->end()
            ->end()
            ->arrayNode('registration')
            ->canBeEnabled()
            ->children()
            ->scalarNode('profile')->defaultValue('default')->end()
            ->arrayNode('routes')
            ->addDefaultsIfNotSet()
            ->children()
            ->scalarNode('host')->defaultNull()->end()
            ->scalarNode('options_path')->defaultValue('/register/options')->end()
            ->scalarNode('result_path')->defaultValue('/register')->end()
            ->end()
            ->end()
            ->scalarNode('options_handler')->defaultValue(DefaultCreationOptionsHandler::class)->end()
            ->end()
            ->end()
            ->end()
        ;
    }

    private function createAuthProvider(ContainerBuilder $container, string $id, string $userProviderId): string
    {
        $providerId = 'security.authentication.provider.webauthn.'.$id;
        $container
            ->setDefinition($providerId, new ChildDefinition(WebauthnProvider::class))
            ->setArgument(1, new Reference($userProviderId))
        ;

        return $providerId;
    }

    /**
     * @param mixed[] $config
     */
    private function createListener(ContainerBuilder $container, string $id, array $config): string
    {
        $this->createRequestControllersAndRoutes($container, $id, $config);
        $requestListenerId = $this->createRequestListener($container, $id, $config);

        $this->createCreationControllersAndRoutes($container, $id, $config);
        $creationListenerId = $this->createCreationListener($container, $id, $config);

        $abstractListenerId = 'security.authentication.listener.webauthn';
        $listener = new ChildDefinition($abstractListenerId);
        $listener->replaceArgument(2, new Reference($requestListenerId));
        $listener->replaceArgument(3, new Reference($creationListenerId));
        $listener->replaceArgument(4, $config);

        $listenerId = $abstractListenerId.'.'.$id;
        $container->setDefinition($listenerId, $listener);

        return $listenerId;
    }

    /**
     * @param mixed[] $config
     */
    private function createRequestControllersAndRoutes(ContainerBuilder $container, string $id, array $config): void
    {
        if (false === $config['authentication']['enabled']) {
            return;
        }

        $this->createControllerAndRoute($container, 'request', 'options', $id, $config['authentication']['routes']['options_path'], $config['authentication']['routes']['host']);
        $this->createControllerAndRoute($container, 'request', 'result', $id, $config['authentication']['routes']['result_path'], $config['authentication']['routes']['host']);
    }

    /**
     * @param mixed[] $config
     */
    private function createRequestListener(ContainerBuilder $container, string $id, array $config): string
    {
        $abstractRequestListenerId = 'security.authentication.listener.webauthn.request';
        $requestListener = new ChildDefinition($abstractRequestListenerId);
        $requestListener->replaceArgument(11, $id);
        $requestListener->replaceArgument(12, $config['authentication']);
        $requestListener->replaceArgument(13, new Reference($config['success_handler']));
        $requestListener->replaceArgument(14, new Reference($config['failure_handler']));
        $requestListener->replaceArgument(15, new Reference($config['authentication']['options_handler']));
        $requestListener->replaceArgument(16, new Reference($config['options_storage']));
        $requestListener->replaceArgument(19, $config['secured_rp_ids']);

        $requestListenerId = $abstractRequestListenerId.'.'.$id;
        $container->setDefinition($requestListenerId, $requestListener);

        return $requestListenerId;
    }

    /**
     * @param mixed[] $config
     */
    private function createCreationControllersAndRoutes(ContainerBuilder $container, string $id, array $config): void
    {
        if (false === $config['registration']['enabled']) {
            return;
        }

        $this->createControllerAndRoute($container, 'creation', 'options', $id, $config['registration']['routes']['options_path'], $config['registration']['routes']['host']);
        $this->createControllerAndRoute($container, 'creation', 'result', $id, $config['registration']['routes']['result_path'], $config['registration']['routes']['host']);
    }

    /**
     * @param mixed[] $config
     */
    private function createCreationListener(ContainerBuilder $container, string $id, array $config): string
    {
        $abstractCreationListenerId = 'security.authentication.listener.webauthn.creation';
        $creationListener = new ChildDefinition($abstractCreationListenerId);
        $creationListener->replaceArgument(11, $id);
        $creationListener->replaceArgument(12, $config['registration']);
        $creationListener->replaceArgument(13, new Reference($config['success_handler']));
        $creationListener->replaceArgument(14, new Reference($config['failure_handler']));
        $creationListener->replaceArgument(15, new Reference($config['registration']['options_handler']));
        $creationListener->replaceArgument(16, new Reference($config['options_storage']));
        $creationListener->replaceArgument(19, $config['secured_rp_ids']);

        $creationListenerId = $abstractCreationListenerId.'.'.$id;
        $container->setDefinition($creationListenerId, $creationListener);

        return $creationListenerId;
    }

    /**
     * @param mixed[] $config
     */
    private function createEntryPoint(ContainerBuilder $container, string $id, array $config): string
    {
        $entryPointId = 'security.authentication.entrypoint.'.$id;
        $entryPoint = new ChildDefinition(WebauthnEntryPoint::class);
        $entryPoint->replaceArgument(0, new Reference($config['failure_handler']));

        $container->setDefinition($entryPointId, $entryPoint);

        return $entryPointId;
    }

    private function createControllerAndRoute(ContainerBuilder $container, string $name, string $operation, string $id, string $path, ?string $host): void
    {
        $controller = new Definition(DummyController::class);
        $controller->setFactory([new Reference(DummyControllerFactory::class), 'create']);
        $controller->addTag(DynamicRouteCompilerPass::TAG, ['path' => $path, 'host' => $host]);
        $controller->addTag('controller.service_arguments');

        $controllerId = sprintf('webauthn.controller.security.%s.%s.%s', $name, $operation, $id);
        $container->setDefinition($controllerId, $controller);
    }
}
