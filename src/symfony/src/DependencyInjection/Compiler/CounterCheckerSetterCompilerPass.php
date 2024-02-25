<?php

declare(strict_types=1);

namespace Webauthn\Bundle\DependencyInjection\Compiler;

use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Reference;
use Webauthn\CeremonyStep\CeremonyStepManagerFactory;
use Webauthn\Counter\CounterChecker;

final class CounterCheckerSetterCompilerPass implements CompilerPassInterface
{
    public function process(ContainerBuilder $container): void
    {
        if (
            ! $container->hasAlias(CounterChecker::class)
            || ! $container->hasDefinition(CeremonyStepManagerFactory::class)
        ) {
            return;
        }

        $definition = $container->getDefinition(CeremonyStepManagerFactory::class);
        $definition->addMethodCall('setCounterChecker', [new Reference(CounterChecker::class)]);
    }
}
