<?php

declare(strict_types=1);

namespace Webauthn\Tests\Bundle\Functional\CompilerPass;

use Matthias\SymfonyDependencyInjectionTest\PhpUnit\AbstractCompilerPassTestCase;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\DependencyInjection\Compiler\PassConfig;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Reference;
use Webauthn\Bundle\DependencyInjection\Compiler\CounterCheckerSetterCompilerPass;
use Webauthn\CeremonyStep\CeremonyStepManagerFactory;
use Webauthn\Counter\CounterChecker;

/**
 * @internal
 */
final class CounterCheckerSetterCompilerPassTest extends AbstractCompilerPassTestCase
{
    #[Test]
    public function theCounterCheckerIsCorrectlyAddedIfItExists(): void
    {
        //Given
        $this->setDefinition(CeremonyStepManagerFactory::class, new Definition());

        $this->setDefinition('counter_checker', new Definition());
        $this->container->setAlias(CounterChecker::class, 'counter_checker');

        //When
        $this->compile();

        //Then
        $this->assertContainerBuilderHasServiceDefinitionWithMethodCall(
            CeremonyStepManagerFactory::class,
            'setCounterChecker',
            [new Reference(CounterChecker::class)]
        );
    }

    protected function registerCompilerPass(ContainerBuilder $container): void
    {
        $container->addCompilerPass(
            new CounterCheckerSetterCompilerPass(),
            PassConfig::TYPE_BEFORE_OPTIMIZATION,
            0
        );
    }
}
