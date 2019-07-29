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

use function Safe\sprintf;
use Symfony\Bundle\SecurityBundle\DependencyInjection\Security\Factory\SecurityFactoryInterface;
use Symfony\Component\Config\Definition\Builder\ArrayNodeDefinition;
use Symfony\Component\Config\Definition\Builder\NodeDefinition;
use Symfony\Component\DependencyInjection\ChildDefinition;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Reference;
use Webauthn\Bundle\Controller\AttestationRequestController;
use Webauthn\Bundle\Controller\AttestationResponseController;
use Webauthn\Bundle\Controller\AttestationResponseControllerFactory;
use Webauthn\Bundle\DependencyInjection\Compiler\DynamicRouteCompilerPass;
use Webauthn\Bundle\Security\Authentication\Provider\WebauthnProvider;
use Webauthn\Bundle\Security\EntryPoint\WebauthnEntryPoint;
use Webauthn\Bundle\Security\Handler\DefaultAuthenticationFailureHandler;
use Webauthn\Bundle\Security\Handler\DefaultAuthenticationSuccessHandler;
use Webauthn\Bundle\Security\Handler\DefaultCreationFailureHandler;
use Webauthn\Bundle\Security\Handler\DefaultRequestOptionsHandler;
use Webauthn\Bundle\Security\Storage\SessionStorage;

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
        $entryPointId = $this->createEntryPoint($container, $id, $config);
        $listenerId = $this->createListener($container, $id, $userProviderId, $config);

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
            ->children()
                ->scalarNode('profile')->isRequired()->end()
                ->scalarNode('options_path')->defaultValue('/login/options')->end()
                ->scalarNode('login_path')->defaultValue('/login')->end()
                ->scalarNode('host')->defaultNull()->end()
                ->scalarNode('user_provider')->defaultNull()->end()
                ->scalarNode('request_options_storage')->defaultValue(SessionStorage::class)->setDeprecated('will be removed in v3.0. Please use "options_storage instead"')->end()
                ->scalarNode('options_storage')->defaultNull()->end()
                ->scalarNode('request_options_handler')->defaultValue(DefaultRequestOptionsHandler::class)->end()
                ->scalarNode('success_handler')->defaultValue(DefaultAuthenticationSuccessHandler::class)->end()
                ->scalarNode('failure_handler')->defaultValue(DefaultAuthenticationFailureHandler::class)->end()
                ->scalarNode('http_message_factory')->isRequired()->end()
                ->scalarNode('fake_user_entity_provider')->defaultNull()->end()
                ->arrayNode('registration')
                    ->canBeEnabled()
                    ->children()
                        ->scalarNode('profile')->isRequired()->end()
                        ->scalarNode('options_path')->defaultValue('/register/options')->end()
                        ->scalarNode('registration_path')->defaultValue('/register')->end()
                        ->booleanNode('login_after_registration')->defaultFalse()->end()
                        ->scalarNode('success_handler')->isRequired()->end()
                        ->scalarNode('failure_handler')->defaultValue(DefaultCreationFailureHandler::class)->end()
                    ->end()
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

    private function createListener(ContainerBuilder $container, string $id, string $userProviderId, array $config): string
    {
        $optionsStorage = $config['request_options_storage'];
        if (isset($config['options_storage']) && null !== $config['options_storage']) {
            $optionsStorage = $config['options_storage'];
        }
        $listenerId = 'security.authentication.listener.webauthn.json';
        $listener = new ChildDefinition($listenerId);
        $listener->replaceArgument(0, new Reference($config['http_message_factory']));
        $listener->replaceArgument(13, null === $config['fake_user_entity_provider'] ? null : new Reference($config['fake_user_entity_provider']));
        $listener->replaceArgument(14, $id);
        $listener->replaceArgument(15, $config);
        $listener->replaceArgument(16, new Reference($config['success_handler']));
        $listener->replaceArgument(17, new Reference($config['failure_handler']));
        $listener->replaceArgument(18, new Reference($config['request_options_handler']));
        $listener->replaceArgument(19, new Reference($optionsStorage));

        $listenerId .= '.'.$id;
        $container->setDefinition($listenerId, $listener);

        $this->createRegistration($container, $id, $userProviderId, $optionsStorage, $config['host'], $config['registration']);

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

    private function createRegistration(ContainerBuilder $container, string $providerKey, string $userProviderId, string $optionStorage, ?string $host, array $options): void
    {
        if (false === $options['enabled']) {
            return;
        }
        $attestationRequestControllerId = sprintf('webauthn.security.json.registration.request.%s', $providerKey);
        $attestationRequestController = new Definition(AttestationRequestController::class);
        $attestationRequestController->setFactory([new Reference(AttestationResponseControllerFactory::class), 'createAttestationRequestController']);
        $attestationRequestController->setArguments([$options['profile'], new Reference($optionStorage)]);
        $attestationRequestController->addTag(DynamicRouteCompilerPass::TAG, ['path' => $options['options_path'], 'host' => $host]);
        $attestationRequestController->addTag('controller.service_arguments');
        $container->setDefinition($attestationRequestControllerId, $attestationRequestController);

        $attestationResponseControllerId = sprintf('webauthn.security.json.registration.response.%s', $providerKey);
        $attestationResponseController = new Definition(AttestationResponseController::class);
        $attestationResponseController->setFactory([new Reference(AttestationResponseControllerFactory::class), 'createAttestationResponseController']);
        $attestationResponseController->setArguments([$providerKey, new Reference($userProviderId), new Reference($options['success_handler']), new Reference($options['failure_handler']), new Reference($optionStorage)]);
        $attestationResponseController->addTag(DynamicRouteCompilerPass::TAG, ['path' => $options['registration_path'], 'host' => $host]);
        $attestationResponseController->addTag('controller.service_arguments');
        $container->setDefinition($attestationResponseControllerId, $attestationResponseController);
    }
}
