<?php

declare(strict_types=1);

namespace Webauthn\Bundle\DependencyInjection;

use function array_key_exists;
use Cose\Algorithm\Algorithm;
use function count;
use function is_array;
use Symfony\Component\Config\Definition\ConfigurationInterface;
use Symfony\Component\Config\Definition\Processor;
use Symfony\Component\Config\FileLocator;
use Symfony\Component\Config\Loader\FileLoader;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Extension\Extension;
use Symfony\Component\DependencyInjection\Extension\PrependExtensionInterface;
use Symfony\Component\DependencyInjection\Loader\PhpFileLoader;
use Symfony\Component\DependencyInjection\Reference;
use Symfony\Component\Serializer\SerializerInterface;
use Symfony\Component\Validator\Validator\ValidatorInterface;
use Webauthn\AttestationStatement\AttestationStatementSupport;
use Webauthn\AuthenticationExtensions\ExtensionOutputChecker;
use Webauthn\Bundle\Controller\AssertionControllerFactory;
use Webauthn\Bundle\Controller\AssertionRequestController;
use Webauthn\Bundle\Controller\AssertionResponseController;
use Webauthn\Bundle\Controller\AttestationControllerFactory;
use Webauthn\Bundle\Controller\AttestationRequestController;
use Webauthn\Bundle\Controller\AttestationResponseController;
use Webauthn\Bundle\CredentialOptionsBuilder\ProfileBasedCreationOptionsBuilder;
use Webauthn\Bundle\CredentialOptionsBuilder\ProfileBasedRequestOptionsBuilder;
use Webauthn\Bundle\DependencyInjection\Compiler\AttestationStatementSupportCompilerPass;
use Webauthn\Bundle\DependencyInjection\Compiler\CoseAlgorithmCompilerPass;
use Webauthn\Bundle\DependencyInjection\Compiler\DynamicRouteCompilerPass;
use Webauthn\Bundle\DependencyInjection\Compiler\EventDispatcherSetterCompilerPass;
use Webauthn\Bundle\DependencyInjection\Compiler\ExtensionOutputCheckerCompilerPass;
use Webauthn\Bundle\DependencyInjection\Compiler\LoggerSetterCompilerPass;
use Webauthn\Bundle\Doctrine\Type as DbalType;
use Webauthn\Bundle\Repository\PublicKeyCredentialUserEntityRepository;
use Webauthn\Bundle\Service\PublicKeyCredentialCreationOptionsFactory;
use Webauthn\Bundle\Service\PublicKeyCredentialRequestOptionsFactory;
use Webauthn\Counter\CounterChecker;
use Webauthn\MetadataService\CanLogData;
use Webauthn\MetadataService\CertificateChain\CertificateChainValidator;
use Webauthn\MetadataService\Event\CanDispatchEvents;
use Webauthn\MetadataService\MetadataStatementRepository;
use Webauthn\MetadataService\StatusReportRepository;
use Webauthn\PublicKeyCredentialSourceRepository;
use Webauthn\TokenBinding\TokenBindingHandler;

final class WebauthnExtension extends Extension implements PrependExtensionInterface
{
    public function __construct(
        private readonly string $alias
    ) {
    }

    /**
     * {@inheritdoc}
     */
    public function getAlias(): string
    {
        return $this->alias;
    }

    public function load(array $configs, ContainerBuilder $container): void
    {
        $processor = new Processor();
        $config = $processor->processConfiguration(
            $this->getConfiguration($configs, $container) ?? new Configuration($this->alias),
            $configs
        );

        $container->registerForAutoconfiguration(AttestationStatementSupport::class)->addTag(
            AttestationStatementSupportCompilerPass::TAG
        );
        $container->registerForAutoconfiguration(ExtensionOutputChecker::class)->addTag(
            ExtensionOutputCheckerCompilerPass::TAG
        );
        $container->registerForAutoconfiguration(CanDispatchEvents::class)->addTag(
            EventDispatcherSetterCompilerPass::TAG
        );
        $container->registerForAutoconfiguration(CanLogData::class)->addTag(LoggerSetterCompilerPass::TAG);
        $container->registerForAutoconfiguration(Algorithm::class)->addTag(CoseAlgorithmCompilerPass::TAG);

        $container->setAlias('webauthn.event_dispatcher', $config['event_dispatcher']);
        $container->setAlias('webauthn.clock', $config['clock']);
        $container->setAlias('webauthn.request_factory', $config['request_factory']);
        $container->setAlias('webauthn.http_client', $config['http_client']);
        $container->setAlias('webauthn.logger', $config['logger']);

        $container->setAlias(PublicKeyCredentialSourceRepository::class, $config['credential_repository']);
        $container->setAlias(PublicKeyCredentialUserEntityRepository::class, $config['user_repository']);

        if ($config['token_binding_support_handler'] !== null) {
            $container->setAlias(TokenBindingHandler::class, $config['token_binding_support_handler']);
        }
        $container->setAlias(CounterChecker::class, $config['counter_checker']);

        $loader = new PhpFileLoader($container, new FileLocator(__DIR__ . '/../Resources/config/'));
        $this->loadAndroidSafetyNet($container, $loader, $config['android_safetynet']);
        $this->loadMetadataServices($container, $loader, $config['metadata']);
        $this->loadControllersSupport($container, $loader, $config['controllers']);

        $container->setParameter('webauthn.creation_profiles', $config['creation_profiles']);
        $container->setParameter('webauthn.request_profiles', $config['request_profiles']);

        $loader->load('services.php');
        $loader->load('cose.php');
        $loader->load('security.php');

        if ($container->hasParameter('kernel.debug') && $container->getParameter('kernel.debug') === true) {
            $loader->load('dev_services.php');
        }
    }

    public function getConfiguration(array $config, ContainerBuilder $container): ?ConfigurationInterface
    {
        return new Configuration($this->alias);
    }

    /**
     * {@inheritdoc}
     */
    public function prepend(ContainerBuilder $container): void
    {
        if (! $container->hasParameter('kernel.bundles')) {
            return;
        }
        $bundles = $container->getParameter('kernel.bundles');
        if (! is_array($bundles) || ! array_key_exists('DoctrineBundle', $bundles)) {
            return;
        }
        $configs = $container->getExtensionConfig('doctrine');
        if (count($configs) === 0) {
            return;
        }
        $config = current($configs);
        if (! isset($config['dbal'])) {
            $config['dbal'] = [];
        }
        if (! isset($config['dbal']['types'])) {
            $config['dbal']['types'] = [];
        }
        $config['dbal']['types'] += [
            'attested_credential_data' => DbalType\AttestedCredentialDataType::class,
            'aaguid' => DbalType\AAGUIDDataType::class,
            'base64' => DbalType\Base64BinaryDataType::class,
            'public_key_credential_descriptor' => DbalType\PublicKeyCredentialDescriptorType::class,
            'public_key_credential_descriptor_collection' => DbalType\PublicKeyCredentialDescriptorCollectionType::class,
            'trust_path' => DbalType\TrustPathDataType::class,
        ];
        $container->prependExtensionConfig('doctrine', $config);
    }

    /**
     * @param mixed[] $config
     */
    private function loadControllersSupport(ContainerBuilder $container, FileLoader $loader, array $config): void
    {
        if ($config['enabled'] === false) {
            return;
        }

        $loader->load('controller.php');
        $this->loadCreationControllersSupport($container, $config['creation'] ?? []);
        $this->loadRequestControllersSupport($container, $config['request'] ?? []);
    }

    /**
     * @param mixed[] $config
     */
    private function loadCreationControllersSupport(ContainerBuilder $container, array $config): void
    {
        foreach ($config as $name => $creationConfig) {
            if ($creationConfig['options_builder'] !== null) {
                $creationOptionsBuilderId = $creationConfig['options_builder'];
            } else {
                $creationOptionsBuilderId = sprintf('webauthn.controller.creation.options_builder.%s', $name);
                $creationOptionsBuilder = (new Definition(ProfileBasedCreationOptionsBuilder::class))
                    ->setArguments([
                        new Reference(SerializerInterface::class),
                        new Reference(ValidatorInterface::class),
                        new Reference(PublicKeyCredentialSourceRepository::class),
                        new Reference(PublicKeyCredentialCreationOptionsFactory::class),
                        $creationConfig['profile'],
                    ]);
                $container->setDefinition($creationOptionsBuilderId, $creationOptionsBuilder);
            }

            $attestationRequestControllerId = sprintf('webauthn.controller.creation.request.%s', $name);
            $attestationRequestController = (new Definition(AttestationRequestController::class))
                ->setFactory([new Reference(AttestationControllerFactory::class), 'createRequestController'])
                ->setArguments([
                    new Reference($creationOptionsBuilderId),
                    new Reference($creationConfig['user_entity_guesser']),
                    new Reference($creationConfig['options_storage']),
                    new Reference($creationConfig['options_handler']),
                    new Reference($creationConfig['failure_handler']),
                ])
                ->addTag(DynamicRouteCompilerPass::TAG, [
                    'method' => $creationConfig['options_method'],
                    'path' => $creationConfig['options_path'],
                    'host' => $creationConfig['host'],
                ])
                ->addTag('controller.service_arguments');
            $container->setDefinition($attestationRequestControllerId, $attestationRequestController);

            $attestationResponseControllerId = sprintf('webauthn.controller.creation.response.%s', $name);
            $attestationResponseController = new Definition(AttestationResponseController::class);
            $attestationResponseController->setFactory(
                [new Reference(AttestationControllerFactory::class), 'createResponseController']
            );
            $attestationResponseController->setArguments([
                new Reference($creationConfig['options_storage']),
                new Reference($creationConfig['success_handler']),
                new Reference($creationConfig['failure_handler']),
                $creationConfig['secured_rp_ids'],
            ]);
            $attestationResponseController->addTag(DynamicRouteCompilerPass::TAG, [
                'method' => $creationConfig['result_method'],
                'path' => $creationConfig['result_path'],
                'host' => $creationConfig['host'],
            ]);
            $attestationResponseController->addTag('controller.service_arguments');
            $container->setDefinition($attestationResponseControllerId, $attestationResponseController);
        }
    }

    /**
     * @param mixed[] $config
     */
    private function loadRequestControllersSupport(ContainerBuilder $container, array $config): void
    {
        foreach ($config as $name => $requestConfig) {
            if ($requestConfig['options_builder'] !== null) {
                $assertionOptionsBuilderId = $requestConfig['options_builder'];
            } else {
                $assertionOptionsBuilderId = sprintf('webauthn.controller.request.options_builder.%s', $name);
                $assertionOptionsBuilder = (new Definition(ProfileBasedRequestOptionsBuilder::class))
                    ->setArguments([
                        new Reference(SerializerInterface::class),
                        new Reference(ValidatorInterface::class),
                        new Reference(PublicKeyCredentialUserEntityRepository::class),
                        new Reference(PublicKeyCredentialSourceRepository::class),
                        new Reference(PublicKeyCredentialRequestOptionsFactory::class),
                        $requestConfig['profile'],
                    ]);
                $container->setDefinition($assertionOptionsBuilderId, $assertionOptionsBuilder);
            }

            $assertionRequestControllerId = sprintf('webauthn.controller.request.request.%s', $name);
            $assertionRequestController = (new Definition(AssertionRequestController::class))
                ->setFactory([new Reference(AssertionControllerFactory::class), 'createRequestController'])
                ->setArguments([
                    new Reference($assertionOptionsBuilderId),
                    new Reference($requestConfig['options_storage']),
                    new Reference($requestConfig['options_handler']),
                    new Reference($requestConfig['failure_handler']),
                    $requestConfig['secured_rp_ids'],
                ])
                ->addTag(DynamicRouteCompilerPass::TAG, [
                    'method' => $requestConfig['options_method'],
                    'path' => $requestConfig['options_path'],
                    'host' => $requestConfig['host'],
                ])
                ->addTag('controller.service_arguments');
            $container->setDefinition($assertionRequestControllerId, $assertionRequestController);

            $assertionResponseControllerId = sprintf('webauthn.controller.request.response.%s', $name);
            $assertionResponseController = new Definition(AssertionResponseController::class);
            $assertionResponseController->setFactory(
                [new Reference(AssertionControllerFactory::class), 'createResponseController']
            );
            $assertionResponseController->setArguments([
                new Reference($requestConfig['options_storage']),
                new Reference($requestConfig['success_handler']),
                new Reference($requestConfig['failure_handler']),
                $requestConfig['secured_rp_ids'],
            ]);
            $assertionResponseController->addTag(DynamicRouteCompilerPass::TAG, [
                'method' => $requestConfig['result_method'],
                'path' => $requestConfig['result_path'],
                'host' => $requestConfig['host'],
            ]);
            $assertionResponseController->addTag('controller.service_arguments');
            $container->setDefinition($assertionResponseControllerId, $assertionResponseController);
        }
    }

    /**
     * @param mixed[] $config
     */
    private function loadAndroidSafetyNet(ContainerBuilder $container, FileLoader $loader, array $config): void
    {
        //Android SafetyNet
        $container->setParameter('webauthn.android_safetynet.leeway', $config['leeway']);
        $container->setParameter('webauthn.android_safetynet.max_age', $config['max_age']);
        $container->setParameter('webauthn.android_safetynet.api_key', $config['api_key']);
        $loader->load('android_safetynet.php');
    }

    /**
     * @param mixed[] $config
     */
    private function loadMetadataServices(ContainerBuilder $container, FileLoader $loader, array $config): void
    {
        if ($config['enabled'] === false) {
            return;
        }
        $container->setAlias(MetadataStatementRepository::class, $config['mds_repository']);
        $container->setAlias(StatusReportRepository::class, $config['status_report_repository']);
        $container->setAlias(CertificateChainValidator::class, $config['certificate_chain_checker']);
        $loader->load('metadata_statement_supports.php');
    }
}
