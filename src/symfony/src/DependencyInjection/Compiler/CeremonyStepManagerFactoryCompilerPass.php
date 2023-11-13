<?php

declare(strict_types=1);

namespace Webauthn\Bundle\DependencyInjection\Compiler;

use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Reference;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AuthenticationExtensions\ExtensionOutputCheckerHandler;
use Webauthn\CeremonyStep\CeremonyStepManagerFactory;
use Webauthn\CeremonyStep\TopOriginValidator;
use Webauthn\MetadataService\CertificateChain\CertificateChainValidator;
use Webauthn\MetadataService\MetadataStatementRepository;
use Webauthn\MetadataService\StatusReportRepository;

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

    private function setSecuredRelyingPartyId(ContainerBuilder $container, Definition $definition): void
    {
        if (! $container->hasParameter('webauthn.secured_relying_party_ids')) {
            return;
        }

        $definition->addMethodCall('setSecuredRelyingPartyId', [
            $container->getParameter('webauthn.secured_relying_party_ids'),
        ]);
    }
}
