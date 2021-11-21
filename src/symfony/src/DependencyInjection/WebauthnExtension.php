<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2021 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Webauthn\Bundle\DependencyInjection;

use function array_key_exists;
use Cose\Algorithm\Algorithm;
use function count;
use function is_array;
use function Safe\sprintf;
use Symfony\Component\Config\Definition\ConfigurationInterface;
use Symfony\Component\Config\Definition\Processor;
use Symfony\Component\Config\FileLocator;
use Symfony\Component\Config\Loader\LoaderInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Extension\Extension;
use Symfony\Component\DependencyInjection\Extension\PrependExtensionInterface;
use Symfony\Component\DependencyInjection\Loader\PhpFileLoader;
use Symfony\Component\DependencyInjection\Reference;
use Webauthn\AttestationStatement\AttestationStatementSupport;
use Webauthn\AuthenticationExtensions\ExtensionOutputChecker;
use Webauthn\Bundle\DependencyInjection\Compiler\AttestationStatementSupportCompilerPass;
use Webauthn\Bundle\DependencyInjection\Compiler\CoseAlgorithmCompilerPass;
use Webauthn\Bundle\DependencyInjection\Compiler\DynamicRouteCompilerPass;
use Webauthn\Bundle\DependencyInjection\Compiler\ExtensionOutputCheckerCompilerPass;
use Webauthn\Bundle\Doctrine\Type as DbalType;
use Webauthn\Bundle\Repository\PublicKeyCredentialUserEntityRepository;
use Webauthn\ConformanceToolset\Controller\AssertionRequestController;
use Webauthn\ConformanceToolset\Controller\AssertionResponseController;
use Webauthn\ConformanceToolset\Controller\AssertionResponseControllerFactory;
use Webauthn\ConformanceToolset\Controller\AttestationRequestController;
use Webauthn\ConformanceToolset\Controller\AttestationResponseController;
use Webauthn\ConformanceToolset\Controller\AttestationResponseControllerFactory;
use Webauthn\Counter\CounterChecker;
use Webauthn\MetadataService\MetadataStatementRepository;
use Webauthn\PublicKeyCredentialSourceRepository;
use Webauthn\TokenBinding\TokenBindingHandler;

final class WebauthnExtension extends Extension implements PrependExtensionInterface
{
    /**
     * @var string
     */
    private $alias;

    public function __construct(string $alias)
    {
        $this->alias = $alias;
    }

    /**
     * {@inheritdoc}
     */
    public function getAlias()
    {
        return $this->alias;
    }

    public function load(array $configs, ContainerBuilder $container): void
    {
        $processor = new Processor();
        $config = $processor->processConfiguration($this->getConfiguration($configs, $container), $configs);

        $container->registerForAutoconfiguration(AttestationStatementSupport::class)->addTag(AttestationStatementSupportCompilerPass::TAG);
        $container->registerForAutoconfiguration(ExtensionOutputChecker::class)->addTag(ExtensionOutputCheckerCompilerPass::TAG);
        $container->registerForAutoconfiguration(Algorithm::class)->addTag(CoseAlgorithmCompilerPass::TAG);

        if (null !== $config['logger']) {
            $container->setAlias('webauthn.logger', $config['logger']);
        }
        $container->setAlias(PublicKeyCredentialSourceRepository::class, $config['credential_repository']);
        $container->setAlias(TokenBindingHandler::class, $config['token_binding_support_handler']);
        $container->setAlias(CounterChecker::class, $config['counter_checker']);
        //FIXME: set default profiles for zero-conf
        $container->setParameter('webauthn.creation_profiles', $config['creation_profiles']);
        $container->setParameter('webauthn.request_profiles', $config['request_profiles']);

        $loader = new PhpFileLoader($container, new FileLocator(__DIR__.'/../Resources/config/'));
        $loader->load('services.php');
        $loader->load('http_message_factory.php');
        $loader->load('cose.php');
        $loader->load('security.php');

        $this->loadTransportBindingProfile($container, $loader, $config);
        $this->loadMetadataServices($container, $config);
        if (true === $config['certificate_chain_checker']['enabled']) {
            $this->loadCertificateChainChecker($container, $loader, $config);
        }

        if (true === $config['metadata_service']['enabled']) {
            $this->loadMetadataStatementSupports($container, $loader, $config);
        }

        if (true === $config['controllers']['enabled']) {
            $this->loadControllerSupport($container, $loader, $config);
        }

        if (null !== $config['user_repository']) {
            $container->setAlias(PublicKeyCredentialUserEntityRepository::class, $config['user_repository']);
        }

        if (true === $container->getParameter('kernel.debug')) {
            $loader->load('dev_services.php');
        }
    }

    public function getConfiguration(array $config, ContainerBuilder $container): ConfigurationInterface
    {
        return new Configuration($this->alias);
    }

    /**
     * @param mixed[] $config
     */
    public function loadTransportBindingProfile(ContainerBuilder $container, LoaderInterface $loader, array $config): void
    {
        if (!class_exists(AttestationRequestController::class)) {
            return;
        }

        $container->setAlias('webauthn.transport_binding_profile.http_message_factory', $config['transport_binding_profile']['http_message_factory']);

        $loader->load('transport_binding_profile.php');

        foreach ($config['transport_binding_profile']['creation'] as $name => $profileConfig) {
            $attestationRequestControllerId = sprintf('webauthn.controller.transport_binding_profile.creation.request.%s', $name);
            $attestationRequestController = new Definition(AttestationRequestController::class);
            $attestationRequestController->setFactory([new Reference(AttestationResponseControllerFactory::class), 'createAttestationRequestController']);
            $attestationRequestController->setArguments([
                $profileConfig['profile_name'],
                $profileConfig['session_parameter_name'],
            ]);
            $attestationRequestController->addTag(DynamicRouteCompilerPass::TAG, ['path' => $profileConfig['request_path'], 'host' => $profileConfig['host']]);
            $attestationRequestController->addTag('controller.service_arguments');
            $container->setDefinition($attestationRequestControllerId, $attestationRequestController);

            $attestationResponseControllerId = sprintf('webauthn.controller.transport_binding_profile.creation.response.%s', $name);
            $attestationResponseController = new Definition(AttestationResponseController::class);
            $attestationResponseController->setFactory([new Reference(AttestationResponseControllerFactory::class), 'createAttestationResponseController']);
            $attestationResponseController->setArguments([
                $profileConfig['session_parameter_name'],
            ]);
            $attestationResponseController->addTag(DynamicRouteCompilerPass::TAG, ['path' => $profileConfig['response_path'], 'host' => $profileConfig['host']]);
            $attestationResponseController->addTag('controller.service_arguments');
            $container->setDefinition($attestationResponseControllerId, $attestationResponseController);
        }

        foreach ($config['transport_binding_profile']['request'] as $name => $profileConfig) {
            $assertionRequestControllerId = sprintf('webauthn.controller.transport_binding_profile.request.request.%s', $name);
            $assertionRequestController = new Definition(AssertionRequestController::class);
            $assertionRequestController->setFactory([new Reference(AssertionResponseControllerFactory::class), 'createAssertionRequestController']);
            $assertionRequestController->setArguments([
                $profileConfig['profile_name'],
                $profileConfig['session_parameter_name'],
            ]);
            $assertionRequestController->addTag(DynamicRouteCompilerPass::TAG, ['path' => $profileConfig['request_path'], 'host' => $profileConfig['host']]);
            $assertionRequestController->addTag('controller.service_arguments');
            $container->setDefinition($assertionRequestControllerId, $assertionRequestController);

            $assertionResponseControllerId = sprintf('webauthn.controller.transport_binding_profile.request.response.%s', $name);
            $assertionResponseController = new Definition(AssertionResponseController::class);
            $assertionResponseController->setFactory([new Reference(AssertionResponseControllerFactory::class), 'createAssertionResponseController']);
            $assertionResponseController->setArguments([$profileConfig['session_parameter_name']]);
            $assertionResponseController->addTag(DynamicRouteCompilerPass::TAG, ['path' => $profileConfig['response_path'], 'host' => $profileConfig['host']]);
            $assertionResponseController->addTag('controller.service_arguments');
            $container->setDefinition($assertionResponseControllerId, $assertionResponseController);
        }
    }

    /**
     * {@inheritdoc}
     */
    public function prepend(ContainerBuilder $container): void
    {
        $bundles = $container->getParameter('kernel.bundles');
        if (!is_array($bundles) || !array_key_exists('DoctrineBundle', $bundles)) {
            return;
        }
        $configs = $container->getExtensionConfig('doctrine');
        if (0 === count($configs)) {
            return;
        }
        $config = current($configs);
        if (!isset($config['dbal'])) {
            $config['dbal'] = [];
        }
        if (!isset($config['dbal']['types'])) {
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
    private function loadControllerSupport(ContainerBuilder $container, LoaderInterface $loader, array $config): void
    {
        $loader->load('controller.php');

        $container->setAlias('webauthn.controller.http_message_factory', $config['controllers']['http_message_factory']);

        foreach ($config['controllers']['creation'] as $name => $creationConfig) {
            $attestationRequestControllerId = sprintf('webauthn.controller.creation.request.%s', $name);
            $attestationRequestController = new Definition(\Webauthn\Bundle\Controller\AttestationRequestController::class);
            $attestationRequestController->setFactory([new Reference(\Webauthn\Bundle\Controller\AttestationResponseControllerFactory::class), 'createAttestationRequestController']);
            $attestationRequestController->setArguments([
                new Reference($creationConfig['user_entity_guesser']),
                $creationConfig['profile'],
                new Reference($creationConfig['options_storage']),
                new Reference($creationConfig['options_handler']),
                new Reference($creationConfig['failure_handler']),
            ]);
            $attestationRequestController->addTag(DynamicRouteCompilerPass::TAG, ['path' => $creationConfig['options_path'], 'host' => $creationConfig['host']]);
            $attestationRequestController->addTag('controller.service_arguments');
            $container->setDefinition($attestationRequestControllerId, $attestationRequestController);

            $attestationResponseControllerId = sprintf('webauthn.controller.creation.response.%s', $name);
            $attestationResponseController = new Definition(\Webauthn\Bundle\Controller\AttestationResponseController::class);
            $attestationResponseController->setFactory([new Reference(\Webauthn\Bundle\Controller\AttestationResponseControllerFactory::class), 'createAttestationResponseController']);
            $attestationResponseController->setArguments([
                new Reference($creationConfig['options_storage']),
                new Reference($creationConfig['success_handler']),
                new Reference($creationConfig['failure_handler']),
            ]);
            $attestationResponseController->addTag(DynamicRouteCompilerPass::TAG, ['path' => $creationConfig['result_path'], 'host' => $creationConfig['host']]);
            $attestationResponseController->addTag('controller.service_arguments');
            $container->setDefinition($attestationResponseControllerId, $attestationResponseController);
        }
    }

    /**
     * @param mixed[] $config
     */
    private function loadCertificateChainChecker(ContainerBuilder $container, LoaderInterface $loader, array $config): void
    {
        $loader->load('certificate_chain_checker.php');
        if (null !== $config['certificate_chain_checker']['http_client']) {
            $container->setAlias('webauthn.certificate_chain_checker.http_client', $config['certificate_chain_checker']['http_client']);
        }
        if (null !== $config['certificate_chain_checker']['request_factory']) {
            $container->setAlias('webauthn.certificate_chain_checker.request_factory', $config['certificate_chain_checker']['request_factory']);
        }
    }

    /**
     * @param mixed[] $config
     */
    private function loadMetadataStatementSupports(ContainerBuilder $container, LoaderInterface $loader, array $config): void
    {
        $loader->load('metadata_statement_supports.php');

        //Android SafetyNet
        if (null !== $config['android_safetynet']['http_client']) {
            $container->setAlias('webauthn.android_safetynet.http_client', $config['android_safetynet']['http_client']);
        }
        if (null !== $config['android_safetynet']['request_factory']) {
            $container->setAlias('webauthn.android_safetynet.request_factory', $config['android_safetynet']['request_factory']);
        }
        $container->setParameter('webauthn.android_safetynet.api_key', $config['android_safetynet']['api_key']);
        $container->setParameter('webauthn.android_safetynet.leeway', $config['android_safetynet']['leeway']);
        $container->setParameter('webauthn.android_safetynet.max_age', $config['android_safetynet']['max_age']);
        $loader->load('android_safetynet.php');
    }

    /**
     * @param mixed[] $config
     */
    private function loadMetadataServices(ContainerBuilder $container, array $config): void
    {
        if (false === $config['metadata_service']['enabled']) {
            return;
        }
        $container->setAlias(MetadataStatementRepository::class, $config['metadata_service']['repository']);
    }
}
