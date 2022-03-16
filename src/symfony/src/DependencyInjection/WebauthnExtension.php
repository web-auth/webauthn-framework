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
use Symfony\Component\Config\Loader\LoaderInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Extension\Extension;
use Symfony\Component\DependencyInjection\Extension\PrependExtensionInterface;
use Symfony\Component\DependencyInjection\Loader\PhpFileLoader;
use Symfony\Component\DependencyInjection\Reference;
use Webauthn\AttestationStatement\AttestationStatementSupport;
use Webauthn\AuthenticationExtensions\ExtensionOutputChecker;
use Webauthn\Bundle\Controller\AttestationControllerFactory;
use Webauthn\Bundle\Controller\AttestationRequestController;
use Webauthn\Bundle\Controller\AttestationResponseController;
use Webauthn\Bundle\DependencyInjection\Compiler\AttestationStatementSupportCompilerPass;
use Webauthn\Bundle\DependencyInjection\Compiler\CoseAlgorithmCompilerPass;
use Webauthn\Bundle\DependencyInjection\Compiler\DynamicRouteCompilerPass;
use Webauthn\Bundle\DependencyInjection\Compiler\ExtensionOutputCheckerCompilerPass;
use Webauthn\Bundle\Doctrine\Type as DbalType;
use Webauthn\Bundle\Repository\PublicKeyCredentialUserEntityRepository;
use Webauthn\Counter\CounterChecker;
use Webauthn\MetadataService\MetadataStatementRepository;
use Webauthn\PublicKeyCredentialSourceRepository;
use Webauthn\TokenBinding\TokenBindingHandler;

final class WebauthnExtension extends Extension implements PrependExtensionInterface
{
    public function __construct(
        private string $alias
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
        $config = $processor->processConfiguration($this->getConfiguration($configs, $container), $configs);

        $container->registerForAutoconfiguration(AttestationStatementSupport::class)->addTag(
            AttestationStatementSupportCompilerPass::TAG
        );
        $container->registerForAutoconfiguration(ExtensionOutputChecker::class)->addTag(
            ExtensionOutputCheckerCompilerPass::TAG
        );
        $container->registerForAutoconfiguration(Algorithm::class)->addTag(CoseAlgorithmCompilerPass::TAG);

        if ($config['logger'] !== null) {
            $container->setAlias('webauthn.logger', $config['logger']);
        }

        $container->setAlias('webauthn.http.factory', $config['http_message_factory']);
        $container->setAlias(PublicKeyCredentialSourceRepository::class, $config['credential_repository']);
        $container->setAlias(TokenBindingHandler::class, $config['token_binding_support_handler']);
        $container->setAlias(CounterChecker::class, $config['counter_checker']);
        $container->setParameter('webauthn.creation_profiles', $config['creation_profiles']);
        $container->setParameter('webauthn.request_profiles', $config['request_profiles']);

        $loader = new PhpFileLoader($container, new FileLocator(__DIR__ . '/../Resources/config/'));
        $loader->load('services.php');
        $loader->load('http_message_factory.php');
        $loader->load('cose.php');
        $loader->load('security.php');
        $loader->load('security.php');

        $this->loadMetadataServices($container, $config);
        if ($config['certificate_chain_checker']['enabled'] === true) {
            $this->loadCertificateChainChecker($container, $loader, $config);
        }

        if ($config['metadata_service']['enabled'] === true) {
            $this->loadMetadataStatementSupports($container, $loader, $config);
        }

        if ($config['controllers']['enabled'] === true) {
            $this->loadControllerSupport($container, $loader, $config);
        }

        if ($config['user_repository'] !== null) {
            $container->setAlias(PublicKeyCredentialUserEntityRepository::class, $config['user_repository']);
        }

        if ($container->getParameter('kernel.debug') === true) {
            $loader->load('dev_services.php');
        }
    }

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
    private function loadControllerSupport(ContainerBuilder $container, LoaderInterface $loader, array $config): void
    {
        $loader->load('controller.php');

        foreach ($config['controllers']['creation'] as $name => $creationConfig) {
            $attestationRequestControllerId = sprintf('webauthn.controller.creation.request.%s', $name);
            $attestationRequestController = (new Definition(AttestationRequestController::class))
                ->setFactory(
                    [new Reference(AttestationControllerFactory::class), 'createAttestationRequestController']
                )
                ->setArguments([
                    new Reference($creationConfig['user_entity_guesser']),
                    $creationConfig['profile'],
                    new Reference($creationConfig['options_storage']),
                    new Reference($creationConfig['options_handler']),
                    new Reference($creationConfig['failure_handler']),
                ])
                ->addTag(DynamicRouteCompilerPass::TAG, [
                    'path' => $creationConfig['options_path'],
                    'host' => $creationConfig['host'],
                ])
                ->addTag('controller.service_arguments')
            ;
            $container->setDefinition($attestationRequestControllerId, $attestationRequestController);

            $attestationResponseControllerId = sprintf('webauthn.controller.creation.response.%s', $name);
            $attestationResponseController = new Definition(AttestationResponseController::class);
            $attestationResponseController->setFactory(
                [new Reference(AttestationControllerFactory::class), 'createAttestationResponseController']
            );
            $attestationResponseController->setArguments([
                new Reference($creationConfig['options_storage']),
                new Reference($creationConfig['success_handler']),
                new Reference($creationConfig['failure_handler']),
                $creationConfig['secured_rp_ids'],
            ]);
            $attestationResponseController->addTag(DynamicRouteCompilerPass::TAG, [
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
    private function loadCertificateChainChecker(
        ContainerBuilder $container,
        LoaderInterface $loader,
        array $config
    ): void {
        $loader->load('certificate_chain_checker.php');
        if ($config['certificate_chain_checker']['http_client'] !== null) {
            $container->setAlias(
                'webauthn.certificate_chain_checker.http_client',
                $config['certificate_chain_checker']['http_client']
            );
        }
        if ($config['certificate_chain_checker']['request_factory'] !== null) {
            $container->setAlias(
                'webauthn.certificate_chain_checker.request_factory',
                $config['certificate_chain_checker']['request_factory']
            );
        }
    }

    /**
     * @param mixed[] $config
     */
    private function loadMetadataStatementSupports(
        ContainerBuilder $container,
        LoaderInterface $loader,
        array $config
    ): void {
        $loader->load('metadata_statement_supports.php');

        //Android SafetyNet
        if ($config['android_safetynet']['http_client'] !== null) {
            $container->setAlias('webauthn.android_safetynet.http_client', $config['android_safetynet']['http_client']);
        }
        if ($config['android_safetynet']['request_factory'] !== null) {
            $container->setAlias(
                'webauthn.android_safetynet.request_factory',
                $config['android_safetynet']['request_factory']
            );
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
        if ($config['metadata_service']['enabled'] === false) {
            return;
        }
        $container->setAlias(MetadataStatementRepository::class, $config['metadata_service']['repository']);
    }
}
