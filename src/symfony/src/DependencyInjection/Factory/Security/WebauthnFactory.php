<?php

declare(strict_types=1);

namespace Webauthn\Bundle\DependencyInjection\Factory\Security;

use Symfony\Bundle\SecurityBundle\DependencyInjection\Security\Factory\AuthenticatorFactoryInterface;
use Symfony\Bundle\SecurityBundle\DependencyInjection\Security\Factory\FirewallListenerFactoryInterface;
use Symfony\Component\Config\Definition\Builder\NodeDefinition;
use Symfony\Component\Config\Definition\Builder\ParentNodeDefinitionInterface;
use Symfony\Component\DependencyInjection\ChildDefinition;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Reference;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Serializer\SerializerInterface;
use Symfony\Component\Validator\Validator\ValidatorInterface;
use Webauthn\Bundle\Controller\AssertionControllerFactory;
use Webauthn\Bundle\Controller\AssertionRequestController;
use Webauthn\Bundle\Controller\AttestationControllerFactory;
use Webauthn\Bundle\Controller\AttestationRequestController;
use Webauthn\Bundle\Controller\DummyController;
use Webauthn\Bundle\Controller\DummyControllerFactory;
use Webauthn\Bundle\CredentialOptionsBuilder\ProfileBasedCreationOptionsBuilder;
use Webauthn\Bundle\CredentialOptionsBuilder\ProfileBasedRequestOptionsBuilder;
use Webauthn\Bundle\DependencyInjection\Compiler\DynamicRouteCompilerPass;
use Webauthn\Bundle\Repository\PublicKeyCredentialSourceRepositoryInterface;
use Webauthn\Bundle\Repository\PublicKeyCredentialUserEntityRepositoryInterface;
use Webauthn\Bundle\Security\Guesser\RequestBodyUserEntityGuesser;
use Webauthn\Bundle\Security\Handler\DefaultCreationOptionsHandler;
use Webauthn\Bundle\Security\Handler\DefaultFailureHandler;
use Webauthn\Bundle\Security\Handler\DefaultRequestOptionsHandler;
use Webauthn\Bundle\Security\Handler\DefaultSuccessHandler;
use Webauthn\Bundle\Security\Storage\SessionStorage;
use Webauthn\Bundle\Service\PublicKeyCredentialCreationOptionsFactory;
use Webauthn\Bundle\Service\PublicKeyCredentialRequestOptionsFactory;
use Webauthn\Denormalizer\WebauthnSerializerFactory;
use Webauthn\FakeCredentialGenerator;
use function array_key_exists;
use function assert;
use function sprintf;

final class WebauthnFactory implements FirewallListenerFactoryInterface, AuthenticatorFactoryInterface
{
    public const AUTHENTICATION_PROVIDER_KEY = 'webauthn';

    public const AUTHENTICATOR_ID_PREFIX = 'security.authenticator.webauthn.';

    public const AUTHENTICATOR_DEFINITION_ID = 'webauthn.security.authenticator';

    public const DEFAULT_SESSION_STORAGE_SERVICE = SessionStorage::class;

    public const DEFAULT_SUCCESS_HANDLER_SERVICE = DefaultSuccessHandler::class;

    public const DEFAULT_FAILURE_HANDLER_SERVICE = DefaultFailureHandler::class;

    public const DEFAULT_LOGIN_OPTIONS_METHOD = Request::METHOD_POST;

    public const DEFAULT_LOGIN_OPTIONS_PATH = '/login/options';

    public const DEFAULT_LOGIN_RESULT_METHOD = Request::METHOD_POST;

    public const DEFAULT_LOGIN_RESULT_PATH = '/login';

    public const DEFAULT_REQUEST_OPTIONS_HANDLER_SERVICE = DefaultRequestOptionsHandler::class;

    public const DEFAULT_REGISTER_OPTIONS_METHOD = Request::METHOD_POST;

    public const DEFAULT_REGISTER_OPTIONS_PATH = '/register/options';

    public const DEFAULT_REGISTER_RESULT_METHOD = Request::METHOD_POST;

    public const DEFAULT_REGISTER_RESULT_PATH = '/register';

    public const DEFAULT_CREATION_OPTIONS_HANDLER_SERVICE = DefaultCreationOptionsHandler::class;

    public const FIREWALL_CONFIG_ID_PREFIX = 'security.firewall_config.webauthn.';

    public const AUTHENTICATOR_ATTESTATION_RESPONSE_VALIDATOR_ID_PREFIX = 'security.authenticator_attestation_response_validator.webauthn.';

    public const AUTHENTICATOR_ASSERTION_RESPONSE_VALIDATOR_ID_PREFIX = 'security.authenticator_assertion_response_validator.webauthn.';

    public const CEREMONY_STEP_MANAGER_ID_PREFIX = 'security.ceremony_step_manager.webauthn.';

    public const FIREWALL_CONFIG_DEFINITION_ID = 'webauthn.security.firewall_config';

    /**
     * @deprecated This constant is not used anymore and will be removed in 5.0
     * @infection-ignore-all
     */
    public const REQUEST_RESULT_LISTENER_DEFINITION_ID = 'webauthn.security.authentication.request_result_listener';

    /**
     * @deprecated This constant is not used anymore and will be removed in 5.0
     * @infection-ignore-all
     */
    public const CREATION_RESULT_LISTENER_DEFINITION_ID = 'webauthn.security.authentication.creation_result_listener';

    /**
     * @deprecated This constant is not used anymore and will be removed in 5.0
     * @infection-ignore-all
     */
    public const SUCCESS_HANDLER_ID_PREFIX = 'security.authentication.success_handler.webauthn.';

    /**
     * @deprecated This constant is not used anymore and will be removed in 5.0
     * @infection-ignore-all
     */
    public const FAILURE_HANDLER_ID_PREFIX = 'security.authentication.failure_handler.webauthn.';

    private const PRIORITY = 0;

    public function __construct(
        private readonly WebauthnServicesFactory $servicesFactory
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
            ->scalarNode('options_builder')
            ->defaultNull()
            ->end()
            ->arrayNode('routes')
            ->addDefaultsIfNotSet()
            ->children()
            ->scalarNode('host')
            ->defaultNull()
            ->end()
            ->scalarNode('options_method')
            ->defaultValue(self::DEFAULT_LOGIN_OPTIONS_METHOD)
            ->end()
            ->scalarNode('options_path')
            ->defaultValue(self::DEFAULT_LOGIN_OPTIONS_PATH)
            ->end()
            ->scalarNode('result_method')
            ->defaultValue(self::DEFAULT_LOGIN_RESULT_METHOD)
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
            ->scalarNode('options_builder')
            ->defaultNull()
            ->end()
            ->arrayNode('routes')
            ->addDefaultsIfNotSet()
            ->children()
            ->scalarNode('host')
            ->defaultNull()
            ->end()
            ->scalarNode('options_method')
            ->defaultValue(self::DEFAULT_REGISTER_OPTIONS_METHOD)
            ->end()
            ->scalarNode('options_path')
            ->defaultValue(self::DEFAULT_REGISTER_OPTIONS_PATH)
            ->end()
            ->scalarNode('result_method')
            ->defaultValue(self::DEFAULT_REGISTER_RESULT_METHOD)
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
            ->end();
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
        $authenticatorAssertionResponseValidatorId = $this->servicesFactory->createAuthenticatorAssertionResponseValidator(
            $container,
            $firewallName,
            $config['secured_rp_ids']
        );
        $authenticatorAttestationResponseValidatorId = $this->servicesFactory->createAuthenticatorAttestationResponseValidator(
            $container,
            $firewallName,
            $config['secured_rp_ids']
        );

        $this->createAssertionControllersAndRoutes($container, $firewallName, $config);
        $this->createAttestationControllersAndRoutes($container, $firewallName, $config);

        return $this->createAuthenticatorService(
            $container,
            $firewallName,
            $userProviderId,
            $config['success_handler'],
            $config['failure_handler'],
            $firewallConfigId,
            $config['options_storage'],
            $authenticatorAssertionResponseValidatorId,
            $authenticatorAttestationResponseValidatorId
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

    private function createAuthenticatorService(
        ContainerBuilder $container,
        string $firewallName,
        string $userProviderId,
        string $successHandlerId,
        string $failureHandlerId,
        string $firewallConfigId,
        string $optionsStorageId,
        string $authenticatorAssertionResponseValidatorId,
        string $authenticatorAttestationResponseValidatorId
    ): string {
        $authenticatorId = self::AUTHENTICATOR_ID_PREFIX . $firewallName;
        $container
            ->setDefinition($authenticatorId, new ChildDefinition(self::AUTHENTICATOR_DEFINITION_ID))
            ->replaceArgument(0, new Reference($firewallConfigId))
            ->replaceArgument(1, new Reference($userProviderId))
            ->replaceArgument(2, new Reference($successHandlerId))
            ->replaceArgument(3, new Reference($failureHandlerId))
            ->replaceArgument(4, new Reference($optionsStorageId))
            ->replaceArgument(8, new Reference($authenticatorAssertionResponseValidatorId))
            ->replaceArgument(9, new Reference($authenticatorAttestationResponseValidatorId))
            ->addMethodCall('setLogger', [new Reference('webauthn.logger')]);

        return $authenticatorId;
    }

    /**
     * @param mixed[] $config
     */
    private function createAssertionControllersAndRoutes(
        ContainerBuilder $container,
        string $firewallName,
        array $config
    ): void {
        if ($config['authentication']['enabled'] === false) {
            return;
        }
        $optionsBuilderId = $this->getAssertionOptionsBuilderId($container, $firewallName, $config['authentication']);

        $this->createAssertionRequestControllerAndRoute(
            $container,
            $firewallName,
            $config['authentication']['routes']['options_method'],
            $config['authentication']['routes']['options_path'],
            $config['authentication']['routes']['host'],
            $optionsBuilderId,
            $config['options_storage'],
            $config['authentication']['options_handler'],
            $config['failure_handler'],
        );
        $this->createResponseControllerAndRoute(
            $container,
            $firewallName,
            'request',
            $config['authentication']['routes']['result_method'],
            $config['authentication']['routes']['result_path'],
            $config['authentication']['routes']['host']
        );
    }

    /**
     * @param mixed[] $config
     */
    private function createAttestationControllersAndRoutes(
        ContainerBuilder $container,
        string $firewallName,
        array $config
    ): void {
        if ($config['registration']['enabled'] === false) {
            return;
        }
        $optionsBuilderId = $this->getAttestationOptionsBuilderId($container, $firewallName, $config['registration']);

        $this->createAttestationRequestControllerAndRoute(
            $container,
            $firewallName,
            $config['registration']['routes']['options_method'],
            $config['registration']['routes']['options_path'],
            $config['registration']['routes']['host'],
            $optionsBuilderId,
            $config['options_storage'],
            $config['registration']['options_handler'],
            $config['failure_handler'],
        );
        $this->createResponseControllerAndRoute(
            $container,
            $firewallName,
            'creation',
            $config['registration']['routes']['result_method'],
            $config['registration']['routes']['result_path'],
            $config['registration']['routes']['host']
        );
    }

    private function createAssertionRequestControllerAndRoute(
        ContainerBuilder $container,
        string $firewallName,
        string $method,
        string $path,
        ?string $host,
        string $optionsBuilderId,
        string $optionsStorageId,
        string $optionsHandlerId,
        string $failureHandlerId,
    ): void {
        $controller = (new Definition(AssertionRequestController::class))
            ->setFactory([new Reference(AssertionControllerFactory::class), 'createRequestController'])
            ->setArguments([
                new Reference($optionsBuilderId),
                new Reference($optionsStorageId),
                new Reference($optionsHandlerId),
                new Reference($failureHandlerId),
            ]);
        $this->createControllerAndRoute(
            $container,
            $controller,
            'request',
            'options',
            $firewallName,
            $method,
            $path,
            $host
        );
    }

    private function createAttestationRequestControllerAndRoute(
        ContainerBuilder $container,
        string $firewallName,
        string $method,
        string $path,
        ?string $host,
        string $optionsBuilderId,
        string $optionsStorageId,
        string $optionsHandlerId,
        string $failureHandlerId,
    ): void {
        $controller = (new Definition(AttestationRequestController::class))
            ->setFactory([new Reference(AttestationControllerFactory::class), 'createRequestController'])
            ->setArguments([
                new Reference($optionsBuilderId),
                new Reference(RequestBodyUserEntityGuesser::class),
                new Reference($optionsStorageId),
                new Reference($optionsHandlerId),
                new Reference($failureHandlerId),
                true,
            ]);
        $this->createControllerAndRoute(
            $container,
            $controller,
            'creation',
            'options',
            $firewallName,
            $method,
            $path,
            $host
        );
    }

    private function createResponseControllerAndRoute(
        ContainerBuilder $container,
        string $firewallName,
        string $action,
        string $method,
        string $path,
        ?string $host
    ): void {
        $controller = (new Definition(DummyController::class))
            ->setFactory([new Reference(DummyControllerFactory::class), 'create']);
        $this->createControllerAndRoute(
            $container,
            $controller,
            $action,
            'result',
            $firewallName,
            $method,
            $path,
            $host
        );
    }

    private function createControllerAndRoute(
        ContainerBuilder $container,
        Definition $controller,
        string $name,
        string $operation,
        string $firewallName,
        string $method,
        string $path,
        ?string $host
    ): void {
        $controller
            ->addTag('controller.service_arguments')
            ->addTag(DynamicRouteCompilerPass::TAG, [
                'method' => $method,
                'path' => $path,
                'host' => $host,
            ])
            ->setPublic(true);

        $controllerId = sprintf('webauthn.controller.security.%s.%s.%s', $firewallName, $name, $operation);

        $container->setDefinition($controllerId, $controller);
    }

    private function getAssertionOptionsBuilderId(
        ContainerBuilder $container,
        string $firewallName,
        array $config
    ): string {
        if (array_key_exists('options_builder', $config) && $config['options_builder'] !== null) {
            return $config['options_builder'];
        }

        $optionsBuilderId = sprintf('webauthn.controller.request.options_builder.firewall.%s', $firewallName);
        $optionsBuilder = (new Definition(ProfileBasedRequestOptionsBuilder::class))
            ->setArguments([
                new Reference(SerializerInterface::class),
                new Reference(ValidatorInterface::class),
                new Reference(PublicKeyCredentialUserEntityRepositoryInterface::class),
                new Reference(PublicKeyCredentialSourceRepositoryInterface::class),
                new Reference(PublicKeyCredentialRequestOptionsFactory::class),
                $config['profile'],
                new Reference(FakeCredentialGenerator::class, ContainerInterface::NULL_ON_INVALID_REFERENCE),
            ]);
        $container->setDefinition($optionsBuilderId, $optionsBuilder);

        return $optionsBuilderId;
    }

    private function getAttestationOptionsBuilderId(
        ContainerBuilder $container,
        string $firewallName,
        array $config
    ): string {
        if (array_key_exists('options_builder', $config) && $config['options_builder'] !== null) {
            return $config['options_builder'];
        }

        $optionsBuilderId = sprintf('webauthn.controller.creation.options_builder.firewall.%s', $firewallName);
        $optionsBuilder = (new Definition(ProfileBasedCreationOptionsBuilder::class))
            ->setArguments([
                new Reference(SerializerInterface::class),
                new Reference(ValidatorInterface::class),
                new Reference(PublicKeyCredentialSourceRepositoryInterface::class),
                new Reference(PublicKeyCredentialCreationOptionsFactory::class),
                $config['profile'],
                new Reference(WebauthnSerializerFactory::class),
            ]);
        $container->setDefinition($optionsBuilderId, $optionsBuilder);

        return $optionsBuilderId;
    }
}
