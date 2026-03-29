<?php

declare(strict_types=1);

namespace Webauthn\Bundle\DependencyInjection\Compiler;

use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Reference;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AuthenticationExtensions\ExtensionOutputCheckerHandler;
use Webauthn\Bundle\Controller\AllowedOriginsController;
use Webauthn\Bundle\Routing\Loader;
use Webauthn\CeremonyStep\CeremonyStepManagerFactory;
use Webauthn\CeremonyStep\TopOriginValidator;
use Webauthn\MetadataService\CertificateChain\CertificateChainValidator;
use Webauthn\MetadataService\MetadataStatementRepository;
use Webauthn\MetadataService\StatusReportRepository;
use function count;
use function is_array;

final class CeremonyStepManagerFactoryCompilerPass implements CompilerPassInterface
{
    public function process(ContainerBuilder $container): void
    {
        if (! $container->hasDefinition(CeremonyStepManagerFactory::class)) {
            return;
        }
        $definition = $container->getDefinition(CeremonyStepManagerFactory::class);
        $this->setAttestationStatementSupportManager($container, $definition);
        $this->setExtensionOutputCheckerHandler($container, $definition);
        $this->enableMetadataStatementSupport($container, $definition);
        $this->enableCertificateChainValidator($container, $definition);
        $this->setAlgorithmManager($container, $definition);
        $this->enableTopOriginValidator($container, $definition);
        $this->setSecuredRelyingPartyId($container, $definition);
        $this->setAllowedOrigins($container, $definition);
    }

    private function setAttestationStatementSupportManager(ContainerBuilder $container, Definition $definition): void
    {
        if (! $container->hasDefinition(AttestationStatementSupportManager::class)) {
            return;
        }

        $definition->addMethodCall(
            'setAttestationStatementSupportManager',
            [new Reference(AttestationStatementSupportManager::class)]
        );
    }

    private function setExtensionOutputCheckerHandler(ContainerBuilder $container, Definition $definition): void
    {
        if (! $container->hasDefinition(ExtensionOutputCheckerHandler::class)) {
            return;
        }

        $definition->addMethodCall(
            'setExtensionOutputCheckerHandler',
            [new Reference(ExtensionOutputCheckerHandler::class)]
        );
    }

    private function enableMetadataStatementSupport(ContainerBuilder $container, Definition $definition): void
    {
        if (
            ! $container->hasAlias(MetadataStatementRepository::class) ||
            ! $container->hasAlias(StatusReportRepository::class) ||
            ! $container->hasAlias(CertificateChainValidator::class)
        ) {
            return;
        }

        $definition->addMethodCall('enableMetadataStatementSupport', [
            new Reference(MetadataStatementRepository::class),
            new Reference(StatusReportRepository::class),
            new Reference(CertificateChainValidator::class),
        ]);
    }

    private function enableCertificateChainValidator(ContainerBuilder $container, Definition $definition): void
    {
        if (! $container->hasDefinition(CertificateChainValidator::class)) {
            return;
        }

        $definition->addMethodCall('enableCertificateChainValidator', [
            new Reference(CertificateChainValidator::class),
        ]);
    }

    private function enableTopOriginValidator(ContainerBuilder $container, Definition $definition): void
    {
        if (! $container->hasDefinition(TopOriginValidator::class) && ! $container->hasAlias(
            TopOriginValidator::class
        )) {
            return;
        }

        $definition->addMethodCall('enableTopOriginValidator', [new Reference(TopOriginValidator::class)]);
    }

    private function setAlgorithmManager(ContainerBuilder $container, Definition $definition): void
    {
        if (! $container->hasDefinition('webauthn.cose.algorithm.manager')) {
            return;
        }

        $definition->addMethodCall('setAlgorithmManager', [new Reference('webauthn.cose.algorithm.manager')]);
    }

    /**
     * @deprecated Will be removed in 6.0.0
     */
    private function setSecuredRelyingPartyId(ContainerBuilder $container, Definition $definition): void
    {
        if (! $container->hasParameter('webauthn.secured_relying_party_ids')) {
            return;
        }

        $definition->addMethodCall('setSecuredRelyingPartyId', [
            $container->getParameter('webauthn.secured_relying_party_ids'),
        ]);
    }

    private function setAllowedOrigins(ContainerBuilder $container, Definition $definition): void
    {
        if (! $container->hasParameter('webauthn.allowed_origins') || $container->getParameter(
            'webauthn.allow_subdomains'
        ) === null) {
            return;
        }
        $allowedOrigins = $container->getParameter('webauthn.allowed_origins');
        if (! is_array($allowedOrigins) || count($allowedOrigins) === 0) {
            return;
        }

        $definition->addMethodCall('setAllowedOrigins', [
            $container->getParameter('webauthn.allowed_origins'),
            $container->getParameter('webauthn.allow_subdomains'),
        ]);
        $this->createControllerDefinition($container);
    }

    private function createControllerDefinition(ContainerBuilder $container): void
    {
        if (! $container->hasDefinition(Loader::class)) {
            return;
        }

        $controllerDefinition = $container->setDefinition(
            AllowedOriginsController::class,
            new Definition(AllowedOriginsController::class, [$container->getParameter('webauthn.allowed_origins')])
        );
        $controllerDefinition->setPublic(true);
        $definition = $container->getDefinition(Loader::class);
        $definition->addMethodCall('add', ['/.well-known/webauthn', null, AllowedOriginsController::class, 'GET']);
    }
}
