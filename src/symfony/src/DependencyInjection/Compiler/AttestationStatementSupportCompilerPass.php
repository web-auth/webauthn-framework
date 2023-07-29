<?php

declare(strict_types=1);

namespace Webauthn\Bundle\DependencyInjection\Compiler;

use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Reference;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;

final class AttestationStatementSupportCompilerPass implements CompilerPassInterface
{
    public const TAG = 'webauthn_attestation_statement_support';

    public function process(ContainerBuilder $container): void
    {
        if (! $container->hasDefinition(AttestationStatementSupportManager::class)) {
            return;
        }

        $definition = $container->getDefinition(AttestationStatementSupportManager::class);
        $taggedServices = $container->findTaggedServiceIds(self::TAG);
        foreach ($taggedServices as $id => $attributes) {
            $definition->addMethodCall('add', [new Reference($id)]);
        }
    }
}
