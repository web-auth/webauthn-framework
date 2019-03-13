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

namespace Webauthn\Bundle\DependencyInjection;

use Cose\Algorithm\Algorithm;
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
use Webauthn\Bundle\Controller\AssertionRequestController;
use Webauthn\Bundle\Controller\AssertionResponseController;
use Webauthn\Bundle\Controller\AssertionResponseControllerFactory;
use Webauthn\Bundle\Controller\AttestationRequestController;
use Webauthn\Bundle\Controller\AttestationResponseController;
use Webauthn\Bundle\Controller\AttestationResponseControllerFactory;
use Webauthn\Bundle\DependencyInjection\Compiler\AttestationStatementSupportCompilerPass;
use Webauthn\Bundle\DependencyInjection\Compiler\CoseAlgorithmCompilerPass;
use Webauthn\Bundle\DependencyInjection\Compiler\DynamicRouteCompilerPass;
use Webauthn\Bundle\DependencyInjection\Compiler\ExtensionOutputCheckerCompilerPass;
use Webauthn\Bundle\Doctrine\Type as DbalType;
use Webauthn\Bundle\Repository\PublicKeyCredentialUserEntityRepository;
use Webauthn\CredentialRepository;
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

    /**
     * {@inheritdoc}
     */
    public function load(array $configs, ContainerBuilder $container): void
    {
        $processor = new Processor();
        $config = $processor->processConfiguration($this->getConfiguration($configs, $container), $configs);

        $container->registerForAutoconfiguration(AttestationStatementSupport::class)->addTag(AttestationStatementSupportCompilerPass::TAG);
        $container->registerForAutoconfiguration(ExtensionOutputChecker::class)->addTag(ExtensionOutputCheckerCompilerPass::TAG);
        $container->registerForAutoconfiguration(Algorithm::class)->addTag(CoseAlgorithmCompilerPass::TAG);

        $container->setAlias(CredentialRepository::class, $config['credential_repository']);
        if (is_subclass_of($config['credential_repository'], PublicKeyCredentialSourceRepository::class)) {
            $container->setAlias(PublicKeyCredentialSourceRepository::class, $config['credential_repository']);
        }
        $container->setAlias(TokenBindingHandler::class, $config['token_binding_support_handler']);
        $container->setParameter('webauthn.creation_profiles', $config['creation_profiles']);
        $container->setParameter('webauthn.request_profiles', $config['request_profiles']);

        $loader = new PhpFileLoader($container, new FileLocator(__DIR__.'/../Resources/config/'));
        $loader->load('services.php');
        $loader->load('cose.php');

        $this->loadTransportBindingProfile($container, $loader, $config);

        if (null !== $config['user_repository']) {
            $container->setAlias(PublicKeyCredentialUserEntityRepository::class, $config['user_repository']);
        }
        if (true === $config['android_safetynet']['enabled']) {
            $container->setAlias('webauthn.android_safetynet.http_client', $config['android_safetynet']['http_client']);
            $container->setParameter('webauthn.android_safetynet.api_key', $config['android_safetynet']['api_key']);
            $loader->load('android_safetynet.php');
        }
    }

    /**
     * {@inheritdoc}
     */
    public function getConfiguration(array $config, ContainerBuilder $container): ConfigurationInterface
    {
        return new Configuration($this->alias);
    }

    public function loadTransportBindingProfile(ContainerBuilder $container, LoaderInterface $loader, array $config): void
    {
        $loader->load('transport_binding_profile.php');

        foreach ($config['transport_binding_profile']['creation'] as $name => $profileConfig) {
            $attestationRequestControllerId = \Safe\sprintf('webauthn.controller.transport_binding_profile.creation.request.%s', $name);
            $attestationRequestController = new Definition(AttestationRequestController::class);
            $attestationRequestController->setFactory([new Reference(AttestationResponseControllerFactory::class), 'createAttestationRequestController']);
            $attestationRequestController->setArguments([$profileConfig['profile_name']]);
            $attestationRequestController->addTag(DynamicRouteCompilerPass::TAG, ['path' => $profileConfig['request_path'], 'host' => $profileConfig['host']]);
            $attestationRequestController->addTag('controller.service_arguments');
            $container->setDefinition($attestationRequestControllerId, $attestationRequestController);

            $attestationResponseControllerId = \Safe\sprintf('webauthn.controller.transport_binding_profile.creation.response.%s', $name);
            $attestationResponseController = new Definition(AttestationResponseController::class);
            $attestationResponseController->setFactory([new Reference(AttestationResponseControllerFactory::class), 'createAttestationResponseController']);
            $attestationResponseController->addTag(DynamicRouteCompilerPass::TAG, ['path' => $profileConfig['response_path'], 'host' => $profileConfig['host']]);
            $attestationResponseController->addTag('controller.service_arguments');
            $container->setDefinition($attestationResponseControllerId, $attestationResponseController);
        }

        foreach ($config['transport_binding_profile']['request'] as $name => $profileConfig) {
            $assertionRequestControllerId = \Safe\sprintf('webauthn.controller.transport_binding_profile.request.request.%s', $name);
            $assertionRequestController = new Definition(AssertionRequestController::class);
            $assertionRequestController->setFactory([new Reference(AssertionResponseControllerFactory::class), 'createAssertionRequestController']);
            $assertionRequestController->setArguments([$profileConfig['profile_name']]);
            $assertionRequestController->addTag(DynamicRouteCompilerPass::TAG, ['path' => $profileConfig['request_path'], 'host' => $profileConfig['host']]);
            $assertionRequestController->addTag('controller.service_arguments');
            $container->setDefinition($assertionRequestControllerId, $assertionRequestController);

            $assertionResponseControllerId = \Safe\sprintf('webauthn.controller.transport_binding_profile.request.response.%s', $name);
            $assertionResponseController = new Definition(AssertionResponseController::class);
            $assertionResponseController->setFactory([new Reference(AssertionResponseControllerFactory::class), 'createAssertionResponseController']);
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
        if (!\is_array($bundles) || !\array_key_exists('DoctrineBundle', $bundles)) {
            return;
        }
        $configs = $container->getExtensionConfig('doctrine');
        if (0 === \count($configs)) {
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
            'base64' => DbalType\Base64BinaryDataType::class,
            'public_key_credential_descriptor' => DbalType\PublicKeyCredentialDescriptorType::class,
            'public_key_credential_descriptor_collection' => DbalType\PublicKeyCredentialDescriptorCollectionType::class,
            'trust_path' => DbalType\TrustPathDataType::class,
        ];
        $container->prependExtensionConfig('doctrine', $config);
    }
}
