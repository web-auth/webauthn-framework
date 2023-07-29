<?php

declare(strict_types=1);

namespace Webauthn\Bundle\DependencyInjection\Compiler;

use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Reference;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\MetadataService\CertificateChain\CertificateChainValidator;
use Webauthn\MetadataService\MetadataStatementRepository;
use Webauthn\MetadataService\StatusReportRepository;

final class MetadataStatementSupportCompilerPass implements CompilerPassInterface
{
    public function process(ContainerBuilder $container): void
    {
        if (! $container->hasAlias(MetadataStatementRepository::class)
            || ! $container->hasAlias(CertificateChainValidator::class)
            || ! $container->hasAlias(StatusReportRepository::class)
        ) {
            return;
        }
        if (! $container->hasDefinition(AuthenticatorAttestationResponseValidator::class)) {
            return;
        }

        $definition = $container->getDefinition(AuthenticatorAttestationResponseValidator::class);
        $definition->addMethodCall(
            'enableMetadataStatementSupport',
            [
                new Reference(MetadataStatementRepository::class),
                new Reference(StatusReportRepository::class),
                new Reference(CertificateChainValidator::class),
            ]
        );
    }
}
