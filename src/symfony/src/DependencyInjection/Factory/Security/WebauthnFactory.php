<?php

declare(strict_types=1);

namespace Webauthn\Bundle\DependencyInjection\Factory\Security;

use function assert;
use Symfony\Bundle\SecurityBundle\DependencyInjection\Security\Factory\AuthenticatorFactoryInterface;
use Symfony\Bundle\SecurityBundle\DependencyInjection\Security\Factory\FirewallListenerFactoryInterface;
use Symfony\Component\Config\Definition\Builder\NodeDefinition;
use Symfony\Component\Config\Definition\Builder\ParentNodeDefinitionInterface;
use Symfony\Component\DependencyInjection\ChildDefinition;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Reference;
use Webauthn\Bundle\Controller\DummyController;
use Webauthn\Bundle\Controller\DummyControllerFactory;
use Webauthn\Bundle\DependencyInjection\Compiler\DynamicRouteCompilerPass;
use Webauthn\Bundle\Security\Handler\DefaultCreationOptionsHandler;
use Webauthn\Bundle\Security\Handler\DefaultFailureHandler;
use Webauthn\Bundle\Security\Handler\DefaultRequestOptionsHandler;
use Webauthn\Bundle\Security\Handler\DefaultSuccessHandler;
use Webauthn\Bundle\Security\Storage\SessionStorage;

final class WebauthnFactory implements FirewallListenerFactoryInterface, AuthenticatorFactoryInterface
{
    public const AUTHENTICATION_PROVIDER_KEY = 'webauthn';

    public const AUTHENTICATOR_ID_PREFIX = 'security.authenticator.webauthn.';

    public const AUTHENTICATOR_DEFINITION_ID = 'webauthn.security.authenticator';

    public const DEFAULT_SESSION_STORAGE_SERVICE = SessionStorage::class;

    public const DEFAULT_HTTP_MESSAGE_FACTORY_SERVICE = 'webauthn.http.factory';

    public const DEFAULT_SUCCESS_HANDLER_SERVICE = DefaultSuccessHandler::class;

    public const DEFAULT_FAILURE_HANDLER_SERVICE = DefaultFailureHandler::class;

    public const DEFAULT_LOGIN_OPTIONS_PATH = '/login/options';

    public const DEFAULT_LOGIN_RESULT_PATH = '/login';

    public const DEFAULT_REQUEST_OPTIONS_HANDLER_SERVICE = DefaultRequestOptionsHandler::class;

    public const DEFAULT_REGISTER_OPTIONS_PATH = '/register/options';

    public const DEFAULT_REGISTER_RESULT_PATH = '/register';

    public const DEFAULT_CREATION_OPTIONS_HANDLER_SERVICE = DefaultCreationOptionsHandler::class;

    public const KERNEL_ACCESS_LISTENER_ID_PREFIX = 'security.authentication.access_listener.webauthn.';

    public const KERNEL_ACCESS_LISTENER_DEFINITION_ID = 'webauthn.security.access_listener';

    public const FIREWALL_CONFIG_ID_PREFIX = 'security.firewall_config.webauthn.';

    public const FIREWALL_CONFIG_DEFINITION_ID = 'webauthn.security.firewall_config';

    public const FIREWALL_CONTEXT_DEFINITION_ID = 'webauthn.firewall_context';

    public const REQUEST_OPTIONS_LISTENER_ID_PREFIX = 'security.authentication.request_options_listener.webauthn.';

    public const REQUEST_OPTIONS_LISTENER_DEFINITION_ID = 'webauthn.security.authentication.request_options_listener';

    public const REQUEST_RESULT_LISTENER_ID_PREFIX = 'security.authentication.request_result_listener.webauthn.';

    public const REQUEST_RESULT_LISTENER_DEFINITION_ID = 'webauthn.security.authentication.request_result_listener';

    public const CREATION_OPTIONS_LISTENER_ID_PREFIX = 'security.authentication.creation_options_listener.webauthn.';

    public const CREATION_OPTIONS_LISTENER_DEFINITION_ID = 'webauthn.security.authentication.creation_options_listener';

    public const CREATION_RESULT_LISTENER_ID_PREFIX = 'security.authentication.creation_result_listener.webauthn.';

    public const CREATION_RESULT_LISTENER_DEFINITION_ID = 'webauthn.security.authentication.creation_result_listener';

    public const SUCCESS_HANDLER_ID_PREFIX = 'security.authentication.success_handler.webauthn.';

    public const FAILURE_HANDLER_ID_PREFIX = 'security.authentication.failure_handler.webauthn.';

    private const PRIORITY = 0;

    public function __construct(
        private WebauthnServicesFactory $servicesFactory
    ) {
    }

    public function getPriority(): int
    {
        return self::PRIORITY;
    }

    public function getKey(): string
    {
        return self::AUTHENTICATION_PROVIDER_KEY;
    }

    public function addConfiguration(NodeDefinition $builder): void
    {
        assert($builder instanceof ParentNodeDefinitionInterface);

        $builder
            ->children()
            ->scalarNode('user_provider')
            ->defaultNull()
            ->end()
            ->scalarNode('options_storage')
            ->defaultValue(self::DEFAULT_SESSION_STORAGE_SERVICE)
            ->end()
            ->scalarNode('http_message_factory')
            ->defaultValue(self::DEFAULT_HTTP_MESSAGE_FACTORY_SERVICE)
            ->end()
            ->scalarNode('success_handler')
            ->defaultValue(self::DEFAULT_SUCCESS_HANDLER_SERVICE)
            ->end()
            ->scalarNode('failure_handler')
            ->defaultValue(self::DEFAULT_FAILURE_HANDLER_SERVICE)
            ->end()
            ->arrayNode('secured_rp_ids')
            ->treatFalseLike([])
            ->treatTrueLike([])
            ->treatNullLike([])
            ->useAttributeAsKey('name')
            ->scalarPrototype()
            ->end()
            ->end()
            ->arrayNode('authentication')
            ->canBeDisabled()
            ->children()
            ->scalarNode('profile')
            ->defaultValue('default')
            ->end()
            ->arrayNode('routes')
            ->addDefaultsIfNotSet()
            ->children()
            ->scalarNode('host')
            ->defaultNull()
            ->end()
            ->scalarNode('options_path')
            ->defaultValue(self::DEFAULT_LOGIN_OPTIONS_PATH)
            ->end()
            ->scalarNode('result_path')
            ->defaultValue(self::DEFAULT_LOGIN_RESULT_PATH)
            ->end()
            ->end()
            ->end()
            ->scalarNode('options_handler')
            ->defaultValue(self::DEFAULT_REQUEST_OPTIONS_HANDLER_SERVICE)
            ->end()
            ->end()
            ->end()
            ->arrayNode('registration')
            ->canBeEnabled()
            ->children()
            ->scalarNode('profile')
            ->defaultValue('default')
            ->end()
            ->arrayNode('routes')
            ->addDefaultsIfNotSet()
            ->children()
            ->scalarNode('host')
            ->defaultNull()
            ->end()
            ->scalarNode('options_path')
            ->defaultValue(self::DEFAULT_REGISTER_OPTIONS_PATH)
            ->end()
            ->scalarNode('result_path')
            ->defaultValue(self::DEFAULT_REGISTER_RESULT_PATH)
            ->end()
            ->end()
            ->end()
            ->scalarNode('options_handler')
            ->defaultValue(self::DEFAULT_CREATION_OPTIONS_HANDLER_SERVICE)
            ->end()
            ->end()
            ->end()
            ->end()
        ;
    }

    /**
     * Creates the authenticator service(s) for the provided configuration.
     *
     * @return string|string[] The authenticator service ID(s) to be used by the firewall
     */
    public function createAuthenticator(
        ContainerBuilder $container,
        string $firewallName,
        array $config,
        string $userProviderId
    ): string|array {
        $firewallConfigId = $this->servicesFactory->createWebauthnFirewallConfig($container, $firewallName, $config);
        $successHandlerId = $this->servicesFactory->createSuccessHandler(
            $container,
            $firewallName,
            $config,
            $firewallConfigId
        );
        $failureHandlerId = $this->servicesFactory->createFailureHandler(
            $container,
            $firewallName,
            $config,
            $firewallConfigId
        );

        $this->createRequestControllersAndRoutes($container, $firewallName, $config);

        //Request Listener
        $this->createRequestOptionsListener($container, $firewallName, $config, $firewallConfigId);
        $this->createRequestResultListener($container, $firewallName, $config, $firewallConfigId);

        //Creation Listener
        //$creationOptionsListenerId = $this->createCreationOptionsListener($container, $firewallName, $config, $firewallConfigId);
        //$creationResultListenerId = $this->createCreationResultListener($container, $firewallName, $config, $firewallConfigId);

        return $this->createAuthenticatorService(
            $container,
            $firewallName,
            $userProviderId,
            $successHandlerId,
            $failureHandlerId,
            $firewallConfigId
        );
    }

    /**
     * Creates the firewall listener services for the provided configuration.
     *
     * @return string[] The listener service IDs to be used by the firewall
     */
    public function createListeners(ContainerBuilder $container, string $firewallName, array $config): array
    {
        return [];
    }

    /**
     * @param mixed[] $config
     */
    private function createRequestOptionsListener(
        ContainerBuilder $container,
        string $firewallName,
        array $config,
        string $firewallConfigId
    ): string {
        $requestListenerId = self::REQUEST_OPTIONS_LISTENER_ID_PREFIX . $firewallName;
        $container
            ->setDefinition($requestListenerId, new ChildDefinition(self::REQUEST_OPTIONS_LISTENER_DEFINITION_ID))
            ->replaceArgument(0, new Reference($firewallConfigId))
            ->replaceArgument(1, new Reference($config['failure_handler']))
            ->replaceArgument(2, new Reference($config['authentication']['options_handler']))
            ->replaceArgument(4, new Reference($config['options_storage']))
        ;

        return $requestListenerId;
    }

    /**
     * @param mixed[] $config
     */
    private function createRequestResultListener(
        ContainerBuilder $container,
        string $firewallName,
        array $config,
        string $firewallConfigId
    ): string {
        $requestResultListenerId = self::REQUEST_RESULT_LISTENER_ID_PREFIX . $firewallName;
        $container
            ->setDefinition(
                $requestResultListenerId,
                new ChildDefinition(self::REQUEST_RESULT_LISTENER_DEFINITION_ID)
            )
            ->replaceArgument(0, new Reference($config['http_message_factory']))
            ->replaceArgument(1, new Reference($firewallConfigId))
            ->replaceArgument(2, new Reference($config['success_handler']))
            ->replaceArgument(3, new Reference($config['failure_handler']))
            ->replaceArgument(4, new Reference($config['options_storage']))
            ->replaceArgument(5, $config['secured_rp_ids'])
        ;

        return $requestResultListenerId;
    }

    private function createAuthenticatorService(
        ContainerBuilder $container,
        string $firewallName,
        string $userProviderId,
        string $successHandlerId,
        string $failureHandlerId,
        string $firewallConfigId,
    ): string {
        $authenticatorId = self::AUTHENTICATOR_ID_PREFIX . $firewallName;
        $container
            ->setDefinition($authenticatorId, new ChildDefinition(self::AUTHENTICATOR_DEFINITION_ID))
            ->replaceArgument(0, new Reference($firewallConfigId))
            ->replaceArgument(1, new Reference($userProviderId))
            ->replaceArgument(2, new Reference($successHandlerId))
            ->replaceArgument(3, new Reference($failureHandlerId))
        ;

        return $authenticatorId;
    }

    /**
     * @param mixed[] $config
     */
    private function createRequestControllersAndRoutes(
        ContainerBuilder $container,
        string $firewallName,
        array $config
    ): void {
        if ($config['authentication']['enabled'] === false) {
            return;
        }

        $this->createControllerAndRoute(
            $container,
            'request',
            'options',
            $firewallName,
            $config['authentication']['routes']['options_path'],
            $config['authentication']['routes']['host']
        );
        $this->createControllerAndRoute(
            $container,
            'request',
            'result',
            $firewallName,
            $config['authentication']['routes']['result_path'],
            $config['authentication']['routes']['host']
        );
    }

    private function createControllerAndRoute(
        ContainerBuilder $container,
        string $name,
        string $operation,
        string $firewallName,
        string $path,
        ?string $host
    ): void {
        $controller = new Definition(DummyController::class);
        $controller->setFactory([new Reference(DummyControllerFactory::class), 'create']);
        $controller->addTag(DynamicRouteCompilerPass::TAG, [
            'path' => $path,
            'host' => $host,
        ]);
        $controller->addTag('controller.service_arguments');

        $controllerId = sprintf('webauthn.controller.security.%s.%s.%s', $name, $operation, $firewallName);

        $container->setDefinition($controllerId, $controller);
    }
}
