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
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Extension\Extension;
use Symfony\Component\DependencyInjection\Extension\PrependExtensionInterface;
use Symfony\Component\DependencyInjection\Loader\PhpFileLoader;
use Webauthn\AttestationStatement\AttestationStatementSupport;
use Webauthn\AuthenticationExtensions\ExtensionOutputChecker;
use Webauthn\Bundle\DependencyInjection\Compiler\AttestationStatementSupportCompilerPass;
use Webauthn\Bundle\DependencyInjection\Compiler\CoseAlgorithmCompilerPass;
use Webauthn\Bundle\DependencyInjection\Compiler\ExtensionOutputCheckerCompilerPass;
use Webauthn\Bundle\Doctrine\Type as DbalType;
use Webauthn\CredentialRepository;
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
        $container->setAlias(TokenBindingHandler::class, $config['token_binding_support_handler']);
        $container->setParameter('webauthn.creation_profiles', $config['creation_profiles']);
        $container->setParameter('webauthn.request_profiles', $config['request_profiles']);

        $loader = new PhpFileLoader($container, new FileLocator(__DIR__.'/../Resources/config/'));
        $loader->load('services.php');
        $loader->load('cose.php');

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
